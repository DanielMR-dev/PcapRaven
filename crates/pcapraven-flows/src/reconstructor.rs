//! Stateful streaming bidirectional flow reconstructor.

use crate::config::FlowReconstructionConfig;
use crate::error::FlowError;
use crate::metrics::{TemporalAccumulator, TrafficAccumulator, exact_duration_between};
use pcapraven_domain::{
    FlowDuration, FlowEndReason, FlowEndpoint, FlowKey, FlowPacketAssociation, FlowRecord,
    FlowReference, IpAddress, NetworkLayer, NormalizedPacket, PacketCompleteness, PacketReference,
    PacketTimestamp, PacketTruncationReason, TransportLayer, TransportProtocol,
    UnsupportedLayerReason,
};
use std::collections::BTreeMap;

pub use pcapraven_domain::FlowExclusionReason;

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
    traffic: TrafficAccumulator,
    temporal: TemporalAccumulator,
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

        // 2. Validate domain packet reference integrity
        if packet.reference.captured_len > packet.reference.original_len {
            return Err(FlowError::InvalidNormalizedPacket {
                detail: "captured_len exceeds original_len in PacketReference",
            });
        }

        // 3. Evaluate flow eligibility
        let net = match &packet.network_layer {
            Some(net) => net,
            None => {
                self.last_seen_ordinal = Some(current_ordinal);
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
                let reason = if net.fragmentation().is_fragmented()
                    || matches!(
                        packet.completeness,
                        PacketCompleteness::Partial {
                            reason: PacketTruncationReason::Fragmented,
                        }
                    ) {
                    FlowExclusionReason::FragmentedWithoutTransport
                } else if matches!(
                    packet.completeness,
                    PacketCompleteness::Unsupported {
                        reason: UnsupportedLayerReason::NetworkProtocol(_)
                            | UnsupportedLayerReason::TransportProtocol(_),
                    }
                ) || (match net {
                    NetworkLayer::Ipv4(ip) => ip.protocol != 6 && ip.protocol != 17,
                    NetworkLayer::Ipv6(ip) => {
                        ip.effective_protocol != 6 && ip.effective_protocol != 17
                    }
                }) {
                    FlowExclusionReason::UnsupportedTransport
                } else {
                    FlowExclusionReason::MissingTransportLayer
                };
                self.last_seen_ordinal = Some(current_ordinal);
                return Ok(FlowReconstructionStep {
                    disposition: FlowDisposition::Excluded(reason),
                    closed_flows: Vec::new(),
                });
            }
        };

        // 4. Validate domain consistency between network layer and transport layer
        validate_domain_consistency(net, transport)?;

        // 5. Extract canonical flow key and endpoints
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

        // 6. Check if an active flow exists for this key
        if let Some(active) = self.active_flows.get(&flow_key) {
            // A. Check idle timeout
            let timed_out = match (&active.last_timestamp, &packet.timestamp) {
                (Some(anchor), current) => has_timed_out(anchor, current, timeout_secs),
                _ => false,
            };

            let is_new_syn = proto == TransportProtocol::Tcp
                && is_initial_syn
                && !active.syn_retransmission_allowed;

            if timed_out || is_new_syn {
                // Preflight: closing the current flow and opening a new one on the same key
                // requires a new flow instance. Verify that maximum_flow_instances permits this
                // BEFORE modifying or removing the existing active flow.
                if self.total_flow_instances >= self.config.maximum_flow_instances {
                    return Err(FlowError::ResourceLimit {
                        limit: "maximum_flow_instances",
                        value: self.total_flow_instances,
                        max: self.config.maximum_flow_instances,
                    });
                }
                let next_ordinal =
                    self.next_flow_ordinal
                        .checked_add(1)
                        .ok_or(FlowError::InternalInvariant {
                            detail: "flow reference ordinal overflow",
                        })?;
                let next_instances = self.total_flow_instances.checked_add(1).ok_or(
                    FlowError::InternalInvariant {
                        detail: "total flow instances overflow",
                    },
                )?;

                // Initialize accumulators for the new flow instance (preflight checks)
                let new_traffic = TrafficAccumulator::new(direction, &packet.reference)?;
                let new_temporal = TemporalAccumulator::new(direction, &packet.timestamp);

                // Now execute the transition atomically
                let end_reason = if timed_out {
                    FlowEndReason::IdleTimeout
                } else {
                    FlowEndReason::TcpNewInitialSyn
                };
                let closed_active =
                    self.active_flows
                        .remove(&flow_key)
                        .ok_or(FlowError::InternalInvariant {
                            detail: "active flow key missing during lifecycle transition",
                        })?;
                let closed_record = FlowRecord::new(
                    closed_active.reference,
                    closed_active.key,
                    closed_active.first_packet,
                    closed_active.last_packet,
                    end_reason,
                    closed_active.traffic.finalize(),
                    closed_active.temporal.finalize(),
                );
                closed_flows.push(closed_record);

                let flow_ref = FlowReference::new(self.next_flow_ordinal);
                self.next_flow_ordinal = next_ordinal;
                self.total_flow_instances = next_instances;

                let association = FlowPacketAssociation::new(flow_ref, packet.reference, direction);

                if is_rst {
                    let rst_closed_record = FlowRecord::new(
                        flow_ref,
                        flow_key,
                        packet.reference,
                        packet.reference,
                        FlowEndReason::TcpReset,
                        new_traffic.finalize(),
                        new_temporal.finalize(),
                    );
                    closed_flows.push(rst_closed_record);
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
                        traffic: new_traffic,
                        temporal: new_temporal,
                    };
                    self.active_flows.insert(flow_key, active_state);
                }

                self.last_seen_ordinal = Some(current_ordinal);
                return Ok(FlowReconstructionStep {
                    disposition: FlowDisposition::Associated(association),
                    closed_flows,
                });
            }

            // Packet belongs to existing active flow instance
            let active =
                self.active_flows
                    .get_mut(&flow_key)
                    .ok_or(FlowError::InternalInvariant {
                        detail: "active flow key missing during active update",
                    })?;

            // Update traffic and temporal accumulators (preflights checked arithmetic)
            active.traffic.observe(direction, &packet.reference)?;
            active.temporal.observe(direction, &packet.timestamp);

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
                let closed_active =
                    self.active_flows
                        .remove(&flow_key)
                        .ok_or(FlowError::InternalInvariant {
                            detail: "active flow key missing during RST termination",
                        })?;
                let closed_record = FlowRecord::new(
                    closed_active.reference,
                    closed_active.key,
                    closed_active.first_packet,
                    closed_active.last_packet,
                    FlowEndReason::TcpReset,
                    closed_active.traffic.finalize(),
                    closed_active.temporal.finalize(),
                );
                closed_flows.push(closed_record);
            }

            self.last_seen_ordinal = Some(current_ordinal);
            return Ok(FlowReconstructionStep {
                disposition: FlowDisposition::Associated(association),
                closed_flows,
            });
        }

        // 7. Create brand new flow instance on a new key
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

        let next_ordinal =
            self.next_flow_ordinal
                .checked_add(1)
                .ok_or(FlowError::InternalInvariant {
                    detail: "flow reference ordinal overflow",
                })?;
        let next_instances =
            self.total_flow_instances
                .checked_add(1)
                .ok_or(FlowError::InternalInvariant {
                    detail: "total flow instances overflow",
                })?;

        let traffic = TrafficAccumulator::new(direction, &packet.reference)?;
        let temporal = TemporalAccumulator::new(direction, &packet.timestamp);

        let flow_ref = FlowReference::new(self.next_flow_ordinal);
        self.next_flow_ordinal = next_ordinal;
        self.total_flow_instances = next_instances;

        let association = FlowPacketAssociation::new(flow_ref, packet.reference, direction);

        if is_rst {
            let closed_record = FlowRecord::new(
                flow_ref,
                flow_key,
                packet.reference,
                packet.reference,
                FlowEndReason::TcpReset,
                traffic.finalize(),
                temporal.finalize(),
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
                traffic,
                temporal,
            };
            self.active_flows.insert(flow_key, active_state);
        }

        self.last_seen_ordinal = Some(current_ordinal);
        Ok(FlowReconstructionStep {
            disposition: FlowDisposition::Associated(association),
            closed_flows,
        })
    }

    /// Finalizes flow reconstruction at the clean end of input, closing all active flows
    /// with [`FlowEndReason::EndOfInput`].
    ///
    /// The returned flow records are deterministically ordered by their [`FlowReference`] ordinal.
    #[must_use]
    pub fn finish(&mut self) -> Vec<FlowRecord> {
        self.drain_with_reason(FlowEndReason::EndOfInput)
    }

    /// Finalizes flow reconstruction when analysis stops before clean end-of-input,
    /// closing all remaining active flows with [`FlowEndReason::AnalysisStopped`].
    ///
    /// The returned flow records are deterministically ordered by their [`FlowReference`] ordinal.
    #[must_use]
    pub fn finish_partial(&mut self) -> Vec<FlowRecord> {
        self.drain_with_reason(FlowEndReason::AnalysisStopped)
    }

    fn drain_with_reason(&mut self, end_reason: FlowEndReason) -> Vec<FlowRecord> {
        let mut closed_flows = Vec::with_capacity(self.active_flows.len());
        for (_, active) in std::mem::take(&mut self.active_flows) {
            closed_flows.push(FlowRecord::new(
                active.reference,
                active.key,
                active.first_packet,
                active.last_packet,
                end_reason,
                active.traffic.finalize(),
                active.temporal.finalize(),
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
    match exact_duration_between(anchor, current) {
        Ok(duration) => duration >= FlowDuration::from_secs(u64::from(timeout_seconds)),
        Err(_) => false,
    }
}
