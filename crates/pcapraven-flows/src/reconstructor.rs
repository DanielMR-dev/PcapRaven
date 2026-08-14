//! Stateful streaming bidirectional flow reconstructor.

use crate::config::FlowReconstructionConfig;
use crate::error::FlowError;
use pcapraven_domain::{
    FlowEndReason, FlowEndpoint, FlowKey, FlowPacketAssociation, FlowRecord, FlowReference,
    IpAddress, NetworkLayer, NormalizedPacket, PacketReference, PacketTimestamp, TransportLayer,
    TransportProtocol,
};
use std::collections::BTreeMap;

/// Reason why a normalized packet was not eligible for flow association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowExclusionReason {
    /// The packet does not contain a normalized network layer.
    MissingNetworkLayer,
    /// The packet does not contain a normalized transport layer.
    MissingTransportLayer,
    /// The packet is an IP fragment without parsed transport headers.
    FragmentedWithoutTransport,
    /// The transport layer protocol is unsupported for flow reconstruction.
    UnsupportedTransport,
}

impl FlowExclusionReason {
    /// Returns a static descriptive label for this exclusion reason.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::MissingNetworkLayer => "MissingNetworkLayer",
            Self::MissingTransportLayer => "MissingTransportLayer",
            Self::FragmentedWithoutTransport => "FragmentedWithoutTransport",
            Self::UnsupportedTransport => "UnsupportedTransport",
        }
    }
}

/// The association outcome of observing a single normalized packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowDisposition {
    /// The packet was associated with a reconstructed flow instance.
    Associated(FlowPacketAssociation),
    /// The packet was not flow-eligible and was excluded from flow association.
    Excluded(FlowExclusionReason),
}

/// Result of observing a single normalized packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowReconstructionStep {
    /// Association disposition for the observed packet.
    pub disposition: FlowDisposition,
    /// Any flow records that were closed during this observation step.
    pub closed_flows: Vec<FlowRecord>,
}

/// Active internal state tracked for an open flow instance.
#[derive(Debug, Clone)]
struct ActiveFlowState {
    reference: FlowReference,
    key: FlowKey,
    first_packet: PacketReference,
    last_packet: PacketReference,
    last_timestamp: Option<PacketTimestamp>,
    syn_retransmission_allowed: bool,
}

/// Stateful streaming engine for deterministic bidirectional flow reconstruction.
#[derive(Debug)]
pub struct FlowReconstructor {
    config: FlowReconstructionConfig,
    last_seen_ordinal: Option<u64>,
    next_flow_ordinal: u64,
    total_flow_instances: usize,
    active_flows: BTreeMap<FlowKey, ActiveFlowState>,
}

impl FlowReconstructor {
    /// Creates a new flow reconstructor with validated configuration.
    pub fn new(config: FlowReconstructionConfig) -> Result<Self, FlowError> {
        config.validate()?;
        Ok(Self {
            config,
            last_seen_ordinal: None,
            next_flow_ordinal: 0,
            total_flow_instances: 0,
            active_flows: BTreeMap::new(),
        })
    }

    /// Returns the configuration governing this reconstructor.
    #[must_use]
    pub const fn config(&self) -> &FlowReconstructionConfig {
        &self.config
    }

    /// Returns the number of currently tracked active flows.
    #[must_use]
    pub fn active_flow_count(&self) -> usize {
        self.active_flows.len()
    }

    /// Returns the total number of flow instances created so far.
    #[must_use]
    pub const fn total_flow_instances(&self) -> usize {
        self.total_flow_instances
    }

    /// Observes a single normalized packet and updates active flow state.
    ///
    /// # Errors
    /// Returns [`FlowError`] if packet ordinals are non-monotonic, if domain facts
    /// are contradictory, or if configured resource limits are reached.
    pub fn observe(
        &mut self,
        packet: &NormalizedPacket,
    ) -> Result<FlowReconstructionStep, FlowError> {
        // 1. Validate strictly increasing packet ordinal in capture stream order
        let current_ordinal = packet.reference.capture_record_ordinal;
        if let Some(prev) = self.last_seen_ordinal {
            if current_ordinal <= prev {
                return Err(FlowError::NonMonotonicPacketOrder {
                    previous_ordinal: prev,
                    current_ordinal,
                });
            }
        }
        self.last_seen_ordinal = Some(current_ordinal);

        // 2. Evaluate flow eligibility
        let net = match &packet.network_layer {
            Some(net) => net,
            None => {
                return Ok(FlowReconstructionStep {
                    disposition: FlowDisposition::Excluded(
                        FlowExclusionReason::MissingNetworkLayer,
                    ),
                    closed_flows: Vec::new(),
                });
            }
        };

        let transport = match &packet.transport_layer {
            Some(transport) => transport,
            None => {
                let reason = if net.fragmentation().is_fragmented() {
                    FlowExclusionReason::FragmentedWithoutTransport
                } else {
                    FlowExclusionReason::MissingTransportLayer
                };
                return Ok(FlowReconstructionStep {
                    disposition: FlowDisposition::Excluded(reason),
                    closed_flows: Vec::new(),
                });
            }
        };

        // 3. Validate domain consistency between network layer and transport layer
        validate_domain_consistency(net, transport)?;

        // 4. Extract canonical flow key and endpoints
        let (src_ip, dst_ip) = match net {
            NetworkLayer::Ipv4(ip) => (IpAddress::Ipv4(ip.source), IpAddress::Ipv4(ip.destination)),
            NetworkLayer::Ipv6(ip) => (IpAddress::Ipv6(ip.source), IpAddress::Ipv6(ip.destination)),
        };

        let (proto, src_port, dst_port, tcp_flags, has_payload) = match transport {
            TransportLayer::Tcp(tcp) => (
                TransportProtocol::Tcp,
                tcp.source_port,
                tcp.destination_port,
                Some(tcp.flags),
                packet.payload.as_ref().is_some_and(|p| !p.is_empty()),
            ),
            TransportLayer::Udp(udp) => (
                TransportProtocol::Udp,
                udp.source_port,
                udp.destination_port,
                None,
                packet.payload.as_ref().is_some_and(|p| !p.is_empty()),
            ),
        };

        let src_endpoint = FlowEndpoint::new(src_ip, src_port);
        let dst_endpoint = FlowEndpoint::new(dst_ip, dst_port);
        let flow_key = FlowKey::new(proto, src_endpoint, dst_endpoint);
        let direction = flow_key.direction_of(src_endpoint, dst_endpoint).ok_or(
            FlowError::InternalInvariant {
                detail: "endpoint mismatch when computing direction for flow key",
            },
        )?;

        let mut closed_flows = Vec::with_capacity(2);
        let is_rst = tcp_flags.is_some_and(|f| f.rst);
        let is_initial_syn = tcp_flags.is_some_and(|f| f.syn && !f.ack);
        let timeout_secs = match proto {
            TransportProtocol::Tcp => self.config.tcp_idle_timeout_seconds,
            TransportProtocol::Udp => self.config.udp_idle_timeout_seconds,
        };

        // 5. Check if an active flow exists for this key
        if let Some(active) = self.active_flows.get_mut(&flow_key) {
            // A. Check idle timeout
            let timed_out = match (&active.last_timestamp, &packet.timestamp) {
                (Some(anchor), current) => has_timed_out(anchor, current, timeout_secs),
                _ => false,
            };

            if timed_out {
                // Close the existing flow with IdleTimeout
                let closed_record = FlowRecord::new(
                    active.reference,
                    active.key,
                    active.first_packet,
                    active.last_packet,
                    FlowEndReason::IdleTimeout,
                );
                closed_flows.push(closed_record);
                self.active_flows.remove(&flow_key);
            } else if proto == TransportProtocol::Tcp
                && is_initial_syn
                && !active.syn_retransmission_allowed
            {
                // New initial SYN observed after activity -> close prior flow with TcpNewInitialSyn
                let closed_record = FlowRecord::new(
                    active.reference,
                    active.key,
                    active.first_packet,
                    active.last_packet,
                    FlowEndReason::TcpNewInitialSyn,
                );
                closed_flows.push(closed_record);
                self.active_flows.remove(&flow_key);
            } else {
                // Stay in existing flow
                let flow_ref = active.reference;
                active.last_packet = packet.reference;
                active.last_timestamp = if packet.timestamp.is_available() {
                    Some(packet.timestamp)
                } else {
                    None
                };

                // Update TCP SYN retransmission allowance
                if let Some(flags) = tcp_flags {
                    if (flags.ack && !flags.syn) || flags.rst || flags.fin || has_payload {
                        active.syn_retransmission_allowed = false;
                    }
                }

                let association = FlowPacketAssociation::new(flow_ref, packet.reference, direction);

                if is_rst {
                    // RST packet belongs to this flow, then terminates it immediately
                    let closed_record = FlowRecord::new(
                        active.reference,
                        active.key,
                        active.first_packet,
                        active.last_packet,
                        FlowEndReason::TcpReset,
                    );
                    closed_flows.push(closed_record);
                    self.active_flows.remove(&flow_key);
                }

                return Ok(FlowReconstructionStep {
                    disposition: FlowDisposition::Associated(association),
                    closed_flows,
                });
            }
        }

        // 6. Create new flow instance
        if self.active_flows.len() >= self.config.maximum_tracked_flows {
            return Err(FlowError::ResourceLimit {
                limit: "maximum_tracked_flows",
                value: self.active_flows.len(),
                max: self.config.maximum_tracked_flows,
            });
        }
        if self.total_flow_instances >= self.config.maximum_flow_instances {
            return Err(FlowError::ResourceLimit {
                limit: "maximum_flow_instances",
                value: self.total_flow_instances,
                max: self.config.maximum_flow_instances,
            });
        }

        let flow_ref = FlowReference::new(self.next_flow_ordinal);
        self.next_flow_ordinal =
            self.next_flow_ordinal
                .checked_add(1)
                .ok_or(FlowError::InternalInvariant {
                    detail: "flow reference ordinal overflow",
                })?;
        self.total_flow_instances =
            self.total_flow_instances
                .checked_add(1)
                .ok_or(FlowError::InternalInvariant {
                    detail: "total flow instances overflow",
                })?;

        let association = FlowPacketAssociation::new(flow_ref, packet.reference, direction);

        if is_rst {
            // If the very first packet of this new flow has RST, it associates with the flow
            // and then closes it immediately with TcpReset
            let closed_record = FlowRecord::new(
                flow_ref,
                flow_key,
                packet.reference,
                packet.reference,
                FlowEndReason::TcpReset,
            );
            closed_flows.push(closed_record);
        } else {
            let active_state = ActiveFlowState {
                reference: flow_ref,
                key: flow_key,
                first_packet: packet.reference,
                last_packet: packet.reference,
                last_timestamp: if packet.timestamp.is_available() {
                    Some(packet.timestamp)
                } else {
                    None
                },
                syn_retransmission_allowed: is_initial_syn,
            };
            self.active_flows.insert(flow_key, active_state);
        }

        Ok(FlowReconstructionStep {
            disposition: FlowDisposition::Associated(association),
            closed_flows,
        })
    }

    /// Finalizes flow reconstruction at the end of input, closing all active flows.
    ///
    /// The returned flow records are deterministically ordered by their [`FlowReference`] ordinal.
    #[must_use]
    pub fn finish(&mut self) -> Vec<FlowRecord> {
        let mut closed_flows = Vec::with_capacity(self.active_flows.len());
        for (_, active) in std::mem::take(&mut self.active_flows) {
            closed_flows.push(FlowRecord::new(
                active.reference,
                active.key,
                active.first_packet,
                active.last_packet,
                FlowEndReason::EndOfInput,
            ));
        }
        closed_flows.sort_by_key(|f| f.reference.ordinal());
        closed_flows
    }
}

fn validate_domain_consistency(
    net: &NetworkLayer,
    transport: &TransportLayer,
) -> Result<(), FlowError> {
    match (net, transport) {
        (NetworkLayer::Ipv4(ip), TransportLayer::Tcp(_)) if ip.protocol != 6 => {
            Err(FlowError::InvalidNormalizedPacket {
                detail: "IPv4 protocol does not equal 6 for TCP transport layer",
            })
        }
        (NetworkLayer::Ipv4(ip), TransportLayer::Udp(_)) if ip.protocol != 17 => {
            Err(FlowError::InvalidNormalizedPacket {
                detail: "IPv4 protocol does not equal 17 for UDP transport layer",
            })
        }
        (NetworkLayer::Ipv6(ip), TransportLayer::Tcp(_)) if ip.effective_protocol != 6 => {
            Err(FlowError::InvalidNormalizedPacket {
                detail: "IPv6 effective_protocol does not equal 6 for TCP transport layer",
            })
        }
        (NetworkLayer::Ipv6(ip), TransportLayer::Udp(_)) if ip.effective_protocol != 17 => {
            Err(FlowError::InvalidNormalizedPacket {
                detail: "IPv6 effective_protocol does not equal 17 for UDP transport layer",
            })
        }
        _ => Ok(()),
    }
}

/// Exact integer-only comparison answering whether `current` has advanced by at least
/// `timeout_seconds` from `anchor`.
///
/// Returns `false` if either timestamp is unavailable, if time moved backward,
/// or if the elapsed time is strictly less than `timeout_seconds`.
#[must_use]
pub fn has_timed_out(
    anchor: &PacketTimestamp,
    current: &PacketTimestamp,
    timeout_seconds: u32,
) -> bool {
    let (s1, f1, r1, o1) = match *anchor {
        PacketTimestamp::Available {
            seconds,
            fractional_units,
            resolution,
            offset_seconds,
        } => (seconds, fractional_units, resolution, offset_seconds),
        PacketTimestamp::Unavailable => return false,
    };

    let (s2, f2, r2, o2) = match *current {
        PacketTimestamp::Available {
            seconds,
            fractional_units,
            resolution,
            offset_seconds,
        } => (seconds, fractional_units, resolution, offset_seconds),
        PacketTimestamp::Unavailable => return false,
    };

    let eff_s1 = match s1.checked_add(i128::from(o1)) {
        Some(s) => s,
        None => return false,
    };
    let eff_s2 = match s2.checked_add(i128::from(o2)) {
        Some(s) => s,
        None => return false,
    };

    // Non-monotonic backward timestamp
    if eff_s2 < eff_s1 {
        return false;
    }

    let diff_seconds = eff_s2.saturating_sub(eff_s1);
    let timeout = i128::from(timeout_seconds);

    if diff_seconds > timeout {
        return true;
    }

    if diff_seconds < timeout {
        return false;
    }

    // Exact whole-second difference == timeout_seconds. Compare fractional units.
    let units1 = u128::from(r1.units_per_second());
    let units2 = u128::from(r2.units_per_second());

    if units1 == 0 || units2 == 0 {
        return false;
    }

    // f2 / units2 >= f1 / units1  <=>  f2 * units1 >= f1 * units2
    let scaled_f2 = match u128::from(f2).checked_mul(units1) {
        Some(v) => v,
        None => return false,
    };
    let scaled_f1 = match u128::from(f1).checked_mul(units2) {
        Some(v) => v,
        None => return false,
    };

    scaled_f2 >= scaled_f1
}
