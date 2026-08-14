use pcap_parser::pcapng::{Block, OptionCode};
use pcap_parser::traits::{PcapNGPacketBlock, PcapReaderIterator};
use pcap_parser::{PcapBlockOwned, PcapError, create_reader};
use std::fmt;
use std::io::{self, Read};

const SHB_MAGIC: u32 = 0x0a0d_0d0a;
const IDB_MAGIC: u32 = 0x0000_0001;
const EPB_MAGIC: u32 = 0x0000_0006;
const SPB_MAGIC: u32 = 0x0000_0003;
const SHB_MAGIC_BYTES: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];
const PCAP_HEADER_SIZE: usize = 24;
const PCAPNG_SHB_MIN_SIZE: usize = 28;
const PCAPNG_BLOCK_HEADER_SIZE: usize = 12;
const PCAPNG_IDB_MIN_SIZE: usize = 20;
const PCAPNG_EPB_MIN_SIZE: usize = 32;
const PCAPNG_SPB_MIN_SIZE: usize = 16;
const INITIAL_PROBE_SIZE: usize = PCAPNG_SHB_MIN_SIZE;

const MAX_ALLOWED_BUFFER_SIZE: usize = 64 * 1024 * 1024;
const MAX_ALLOWED_BLOCK_SIZE: usize = 64 * 1024 * 1024;
const MAX_ALLOWED_PACKET_SIZE: usize = 64 * 1024 * 1024;
const MAX_ALLOWED_RETAINED_PACKET_BYTES: usize = 64 * 1024 * 1024;
const MAX_ALLOWED_INTERFACES: usize = 65_536;
const MAX_ALLOWED_SECTIONS: usize = 65_536;
const MAX_ALLOWED_DIAGNOSTICS: usize = 1_000_000;
const MAX_ALLOWED_RECORDS: usize = 10_000_000;
const MAX_ALLOWED_BLOCKS: usize = 10_000_000;

/// The byte order used by a capture header or PCAPNG section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ByteOrder {
    /// Least significant byte first.
    Little,
    /// Most significant byte first.
    Big,
}

impl ByteOrder {
    fn read_u32(self, bytes: [u8; 4]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }

    fn read_i64(self, bytes: [u8; 8]) -> i64 {
        match self {
            Self::Little => i64::from_le_bytes(bytes),
            Self::Big => i64::from_be_bytes(bytes),
        }
    }
}

/// The capture-container format recognized by the reader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureFormat {
    /// A supported legacy PCAP file.
    LegacyPcap,
    /// A supported PCAPNG file.
    PcapNg,
    /// No format could be established, normally because initialization failed.
    Unknown,
}

/// The effective integer timestamp resolution and its format-specific raw value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureTimestampResolution {
    /// `10^exponent` timestamp units per second.
    Decimal {
        /// The raw decimal exponent stored in the format.
        exponent: u8,
        /// The checked effective units per second.
        units_per_second: u64,
    },
    /// `2^exponent` timestamp units per second.
    Binary {
        /// The raw binary exponent stored in the format.
        exponent: u8,
        /// The checked effective units per second.
        units_per_second: u64,
    },
}

impl CaptureTimestampResolution {
    /// Returns the effective number of timestamp units in one second.
    pub const fn units_per_second(self) -> u64 {
        match self {
            Self::Decimal {
                units_per_second, ..
            }
            | Self::Binary {
                units_per_second, ..
            } => units_per_second,
        }
    }

    /// Returns the raw resolution value represented by this resolution.
    pub const fn raw_value(self) -> u8 {
        match self {
            Self::Decimal { exponent, .. } => exponent,
            Self::Binary { exponent, .. } => exponent | 0x80,
        }
    }
}

/// An integer-only capture timestamp.  PCAPNG SPB records use the explicit
/// [`Unavailable`](CaptureTimestamp::Unavailable) state because SPB has no
/// timestamp field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureTimestamp {
    /// The capture record has no timestamp available in its container format.
    Unavailable,
    /// A timestamp represented without floating-point conversion.
    Available {
        /// Whole seconds before applying `offset_seconds`.
        seconds: i128,
        /// Fractional units in the range `0..units_per_second`.
        fractional_units: u64,
        /// The timestamp resolution used to interpret `fractional_units`.
        resolution: CaptureTimestampResolution,
        /// A signed format-provided offset in seconds.
        offset_seconds: i64,
    },
}

impl CaptureTimestamp {
    /// Constructs an available timestamp after checking the fractional range.
    fn available(
        seconds: i128,
        fractional_units: u64,
        resolution: CaptureTimestampResolution,
        offset_seconds: i64,
    ) -> Option<Self> {
        if fractional_units < resolution.units_per_second() {
            Some(Self::Available {
                seconds,
                fractional_units,
                resolution,
                offset_seconds,
            })
        } else {
            None
        }
    }

    /// Returns the raw whole seconds, if a timestamp is available.
    pub const fn seconds(self) -> Option<i128> {
        match self {
            Self::Unavailable => None,
            Self::Available { seconds, .. } => Some(seconds),
        }
    }

    /// Returns the fractional units, if a timestamp is available.
    pub const fn fractional_units(self) -> Option<u64> {
        match self {
            Self::Unavailable => None,
            Self::Available {
                fractional_units, ..
            } => Some(fractional_units),
        }
    }

    /// Returns the signed format-provided offset, if a timestamp is available.
    pub const fn offset_seconds(self) -> Option<i64> {
        match self {
            Self::Unavailable => None,
            Self::Available { offset_seconds, .. } => Some(offset_seconds),
        }
    }

    /// Returns the timestamp resolution, if a timestamp is available.
    pub const fn resolution(self) -> Option<CaptureTimestampResolution> {
        match self {
            Self::Unavailable => None,
            Self::Available { resolution, .. } => Some(resolution),
        }
    }

    /// Returns the offset-adjusted whole seconds when available.
    pub fn effective_seconds(self) -> Option<i128> {
        match self {
            Self::Unavailable => None,
            Self::Available {
                seconds,
                offset_seconds,
                ..
            } => seconds.checked_add(i128::from(offset_seconds)),
        }
    }

    /// Converts this capture timestamp into a domain [`pcapraven_domain::PacketTimestamp`].
    #[must_use]
    pub fn to_packet_timestamp(self) -> pcapraven_domain::PacketTimestamp {
        match self {
            Self::Unavailable => pcapraven_domain::PacketTimestamp::Unavailable,
            Self::Available {
                seconds,
                fractional_units,
                resolution,
                offset_seconds,
            } => pcapraven_domain::PacketTimestamp::Available {
                seconds,
                fractional_units,
                resolution: match resolution {
                    CaptureTimestampResolution::Decimal {
                        exponent,
                        units_per_second,
                    } => pcapraven_domain::PacketTimestampResolution::Decimal {
                        exponent,
                        units_per_second,
                    },
                    CaptureTimestampResolution::Binary {
                        exponent,
                        units_per_second,
                    } => pcapraven_domain::PacketTimestampResolution::Binary {
                        exponent,
                        units_per_second,
                    },
                },
                offset_seconds,
            },
        }
    }
}

impl From<CaptureTimestamp> for pcapraven_domain::PacketTimestamp {
    fn from(timestamp: CaptureTimestamp) -> Self {
        timestamp.to_packet_timestamp()
    }
}

/// Owned packet bytes extracted from a validated capture record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedPacket {
    bytes: Vec<u8>,
}

impl CapturedPacket {
    fn from_borrowed(bytes: &[u8]) -> Self {
        Self {
            bytes: bytes.to_vec(),
        }
    }

    /// Returns the exact captured bytes without PCAPNG padding.
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the number of retained captured bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether no captured bytes were retained.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl AsRef<[u8]> for CapturedPacket {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

/// A legacy PCAP global header projected into PcapRaven-owned metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureGlobalMetadata {
    /// Header byte order.
    pub byte_order: ByteOrder,
    /// Legacy PCAP major version.
    pub version_major: u16,
    /// Legacy PCAP minor version.
    pub version_minor: u16,
    /// Signed legacy PCAP timestamp correction.
    pub timestamp_offset_seconds: i32,
    /// Capture timestamp accuracy field.
    pub sigfigs: u32,
    /// Declared maximum captured packet length.
    pub snaplen: u32,
    /// Capture link type.
    pub linktype: u32,
    /// Integer timestamp resolution.
    pub timestamp_resolution: CaptureTimestampResolution,
}

/// A section-local PCAPNG interface description.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureInterface {
    /// Zero-based section ordinal.
    pub section_ordinal: u32,
    /// Zero-based interface ordinal within its section.
    pub interface_ordinal: u32,
    /// Interface link type.
    pub linktype: u32,
    /// Interface snap length; zero means no declared bound.
    pub snaplen: u32,
    /// Section byte order used for this interface's metadata.
    pub byte_order: ByteOrder,
    /// Effective interface timestamp resolution.
    pub timestamp_resolution: CaptureTimestampResolution,
    /// Signed interface timestamp offset in seconds.
    pub timestamp_offset_seconds: i64,
}

/// The declaration status of a PCAPNG section-local interface slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureInterfaceSlot {
    /// A usable interface description.
    Valid(CaptureInterface),
    /// An unusable or malformed interface slot that maintains positional identity.
    Unusable {
        /// Zero-based section ordinal.
        section_ordinal: u32,
        /// Zero-based positional interface ordinal within its section.
        interface_ordinal: u32,
    },
}

impl CaptureInterfaceSlot {
    /// Returns the zero-based section ordinal for this interface slot.
    pub const fn section_ordinal(&self) -> u32 {
        match self {
            Self::Valid(interface) => interface.section_ordinal,
            Self::Unusable {
                section_ordinal, ..
            } => *section_ordinal,
        }
    }

    /// Returns the zero-based positional interface ordinal within its section.
    pub const fn interface_ordinal(&self) -> u32 {
        match self {
            Self::Valid(interface) => interface.interface_ordinal,
            Self::Unusable {
                interface_ordinal, ..
            } => *interface_ordinal,
        }
    }

    /// Returns the valid interface description, if available.
    pub const fn as_valid(&self) -> Option<&CaptureInterface> {
        match self {
            Self::Valid(interface) => Some(interface),
            Self::Unusable { .. } => None,
        }
    }

    /// Returns whether this interface slot is usable.
    pub const fn is_valid(&self) -> bool {
        matches!(self, Self::Valid(_))
    }
}

/// Metadata for one PCAPNG section, including its section-local interfaces.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureSection {
    /// Zero-based section ordinal.
    pub ordinal: u32,
    /// Section byte order.
    pub byte_order: ByteOrder,
    /// Section header major version.
    pub version_major: u16,
    /// Section header minor version.
    pub version_minor: u16,
    /// Declared section length, or the format's unspecified sentinel.
    pub section_length: i64,
    /// Interfaces declared in this section, in declaration order.
    pub interfaces: Vec<CaptureInterfaceSlot>,
}

/// Capture-level metadata returned by the reader.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureMetadata {
    /// Recognized format, or [`CaptureFormat::Unknown`] after failed startup.
    pub format: CaptureFormat,
    /// Legacy global header metadata, when the format is legacy PCAP.
    pub legacy: Option<CaptureGlobalMetadata>,
    /// PCAPNG sections in capture order.
    pub sections: Vec<CaptureSection>,
}

impl CaptureMetadata {
    fn unknown() -> Self {
        Self {
            format: CaptureFormat::Unknown,
            legacy: None,
            sections: Vec::new(),
        }
    }
}

/// A stable capture-local location used by diagnostics and errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaptureLocation {
    /// Absolute byte offset in the input stream.
    pub offset: u64,
    /// PCAPNG section ordinal, when known.
    pub section_ordinal: Option<u32>,
    /// Section-local interface ordinal, when known.
    pub interface_ordinal: Option<u32>,
    /// Block type, when a block header was available.
    pub block_type: Option<u32>,
    /// Emitted packet ordinal.  It is intentionally absent for skipped blocks.
    pub packet_ordinal: Option<u64>,
}

impl CaptureLocation {
    fn new(offset: u64) -> Self {
        Self {
            offset,
            section_ordinal: None,
            interface_ordinal: None,
            block_type: None,
            packet_ordinal: None,
        }
    }
}

/// The stage at which a bounded diagnostic was produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureDiagnosticStage {
    /// Format probing and reader initialization.
    Format,
    /// A legacy global header or PCAPNG section header.
    Header,
    /// A capture-container block boundary.
    Block,
    /// A PCAPNG interface description.
    Interface,
    /// A packet-container block.
    Packet,
    /// Streaming reader resource or I/O handling.
    Reader,
}

/// The factual category of a capture diagnostic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureDiagnosticKind {
    /// Valid structure or a recognized feature is outside this subset.
    Unsupported,
    /// A validated block contains contradictory or invalid fields.
    Malformed,
    /// Expected bytes or semantic context were absent.
    Incomplete,
    /// A packet referenced unavailable section-local state.
    InvalidReference,
    /// A configured finite limit prevented safe continuation.
    ResourceLimit,
    /// The input reader returned an error.
    Io,
    /// An internal invariant prevented safe continuation.
    Internal,
}

/// A bounded diagnostic.  Messages are fixed, non-secret templates; numeric
/// attacker-controlled values remain in structured location fields instead of
/// being copied into free-form text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureDiagnostic {
    /// Diagnostic category.
    pub kind: CaptureDiagnosticKind,
    /// Processing stage.
    pub stage: CaptureDiagnosticStage,
    /// Safe fixed diagnostic text.
    pub message: &'static str,
    /// Capture-local context.  Skipped blocks never receive a packet ordinal.
    pub location: CaptureLocation,
    /// Whether the reader continued after this diagnostic.
    pub recovered: bool,
}

/// A public error category independent of the low-level parser dependency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaptureReaderErrorKind {
    /// The caller supplied an invalid finite limit configuration.
    InvalidLimits,
    /// The input was empty or did not identify either supported container.
    UnrecognizedFormat,
    /// A recognized variant is outside the implemented subset.
    Unsupported,
    /// The container structure or fields are invalid.
    Malformed,
    /// The stream ended before a complete structural unit was available.
    Incomplete,
    /// The underlying `Read` operation failed.
    Io,
    /// A configured bound prevented safe continuation.
    ResourceLimit,
    /// A block referenced unavailable section-local state.
    InvalidReference,
    /// A library invariant failed without exposing capture bytes.
    Internal,
}

/// The finite limit whose exhaustion or invalid configuration is reported.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReaderLimit {
    /// Initial streaming buffer size.
    InitialBufferSize,
    /// Maximum streaming buffer size.
    MaximumBufferSize,
    /// Maximum validated capture block size.
    MaximumBlockSize,
    /// Maximum individual packet bytes.
    MaximumPacketBytes,
    /// Maximum aggregate retained packet bytes for collection.
    MaximumRetainedPacketBytes,
    /// Maximum accepted interfaces in one section.
    MaximumInterfacesPerSection,
    /// Maximum accepted PCAPNG sections.
    MaximumSections,
    /// Maximum retained diagnostics.
    MaximumDiagnostics,
    /// Maximum emitted records.
    MaximumRecords,
    /// Maximum processed capture blocks.
    MaximumBlocks,
}

/// Errors returned by reader construction or a terminal streaming operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureReaderError {
    /// Invalid caller-provided limits.
    InvalidLimits { limit: ReaderLimit, value: usize },
    /// No supported format was identified.
    UnrecognizedFormat { location: CaptureLocation },
    /// A recognized format variant is not in the Phase 2 subset.
    Unsupported {
        detail: UnsupportedCapture,
        location: CaptureLocation,
    },
    /// A structural or field-level contradiction was found.
    Malformed {
        detail: MalformedCapture,
        location: CaptureLocation,
    },
    /// The input ended before a complete header or block was available.
    Incomplete { location: CaptureLocation },
    /// The generic input reader failed.
    Io {
        kind: io::ErrorKind,
        location: CaptureLocation,
    },
    /// A configured finite bound prevented safe continuation.
    ResourceLimit {
        limit: ReaderLimit,
        location: CaptureLocation,
    },
    /// A packet block referred to unavailable section-local state.
    InvalidReference { location: CaptureLocation },
    /// A non-capture programming invariant failed.
    Internal { location: CaptureLocation },
}

/// Recognized but unsupported capture variants.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnsupportedCapture {
    /// Legacy modified-PCAP packet records are intentionally not advertised.
    ModifiedPcap,
    /// A legacy PCAP version other than 2.4.
    LegacyVersion,
    /// A PCAPNG section version other than 1.0.
    PcapNgVersion,
}

/// Structural or field-level malformed-input reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MalformedCapture {
    /// A parser boundary or trailing length was contradictory.
    Boundary,
    /// A captured/original/snap length relationship was invalid.
    LengthMismatch,
    /// Timestamp precision metadata or a fractional field was invalid.
    Timestamp,
    /// An invalid global or interface header field was encountered.
    Header,
    /// The low-level parser rejected a bounded block.
    Parser,
}

impl CaptureReaderError {
    /// Returns the PcapRaven-owned error category.
    pub const fn kind(&self) -> CaptureReaderErrorKind {
        match self {
            Self::InvalidLimits { .. } => CaptureReaderErrorKind::InvalidLimits,
            Self::UnrecognizedFormat { .. } => CaptureReaderErrorKind::UnrecognizedFormat,
            Self::Unsupported { .. } => CaptureReaderErrorKind::Unsupported,
            Self::Malformed { .. } => CaptureReaderErrorKind::Malformed,
            Self::Incomplete { .. } => CaptureReaderErrorKind::Incomplete,
            Self::Io { .. } => CaptureReaderErrorKind::Io,
            Self::ResourceLimit { .. } => CaptureReaderErrorKind::ResourceLimit,
            Self::InvalidReference { .. } => CaptureReaderErrorKind::InvalidReference,
            Self::Internal { .. } => CaptureReaderErrorKind::Internal,
        }
    }

    fn location(&self) -> CaptureLocation {
        match self {
            Self::InvalidLimits { .. } => CaptureLocation::new(0),
            Self::UnrecognizedFormat { location }
            | Self::Unsupported { location, .. }
            | Self::Malformed { location, .. }
            | Self::Incomplete { location }
            | Self::Io { location, .. }
            | Self::ResourceLimit { location, .. }
            | Self::InvalidReference { location }
            | Self::Internal { location } => *location,
        }
    }
}

impl fmt::Display for CaptureReaderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits { limit, value } => {
                write!(formatter, "invalid {:?} limit value {}", limit, value)
            }
            Self::UnrecognizedFormat { location } => write!(
                formatter,
                "capture format was not recognized at byte {}",
                location.offset
            ),
            Self::Unsupported { detail, location } => write!(
                formatter,
                "unsupported capture variant {:?} at byte {}",
                detail, location.offset
            ),
            Self::Malformed { detail, location } => write!(
                formatter,
                "malformed capture ({:?}) at byte {}",
                detail, location.offset
            ),
            Self::Incomplete { location } => {
                write!(formatter, "incomplete capture at byte {}", location.offset)
            }
            Self::Io { kind, location } => write!(
                formatter,
                "capture input I/O error ({:?}) at byte {}",
                kind, location.offset
            ),
            Self::ResourceLimit { limit, location } => write!(
                formatter,
                "capture reader limit {:?} reached at byte {}",
                limit, location.offset
            ),
            Self::InvalidReference { location } => write!(
                formatter,
                "invalid section-local capture reference at byte {}",
                location.offset
            ),
            Self::Internal { location } => write!(
                formatter,
                "internal capture-reader invariant at byte {}",
                location.offset
            ),
        }
    }
}

impl std::error::Error for CaptureReaderError {}

/// A validated, finite resource policy for streaming capture reading.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaderLimits {
    initial_buffer_size: usize,
    maximum_buffer_size: usize,
    maximum_block_size: usize,
    maximum_packet_bytes: usize,
    maximum_retained_packet_bytes: usize,
    maximum_interfaces_per_section: usize,
    maximum_sections: usize,
    maximum_diagnostics: usize,
    maximum_records: usize,
    maximum_blocks: usize,
}

impl Default for ReaderLimits {
    fn default() -> Self {
        Self {
            initial_buffer_size: 64 * 1024,
            maximum_buffer_size: 4 * 1024 * 1024,
            maximum_block_size: 4 * 1024 * 1024,
            maximum_packet_bytes: 1024 * 1024,
            maximum_retained_packet_bytes: 16 * 1024 * 1024,
            maximum_interfaces_per_section: 1024,
            maximum_sections: 1024,
            maximum_diagnostics: 256,
            maximum_records: 100_000,
            maximum_blocks: 1_000_000,
        }
    }
}

impl ReaderLimits {
    /// Starts a builder populated with conservative defaults.
    pub fn builder() -> ReaderLimitsBuilder {
        ReaderLimitsBuilder::default()
    }

    /// Validates and constructs limits from all fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        initial_buffer_size: usize,
        maximum_buffer_size: usize,
        maximum_block_size: usize,
        maximum_packet_bytes: usize,
        maximum_retained_packet_bytes: usize,
        maximum_interfaces_per_section: usize,
        maximum_sections: usize,
        maximum_diagnostics: usize,
        maximum_records: usize,
        maximum_blocks: usize,
    ) -> Result<Self, CaptureReaderError> {
        let limits = Self {
            initial_buffer_size,
            maximum_buffer_size,
            maximum_block_size,
            maximum_packet_bytes,
            maximum_retained_packet_bytes,
            maximum_interfaces_per_section,
            maximum_sections,
            maximum_diagnostics,
            maximum_records,
            maximum_blocks,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// Initial streaming buffer size requested by the caller.
    pub const fn initial_buffer_size(&self) -> usize {
        self.initial_buffer_size
    }

    /// Maximum streaming buffer size.
    pub const fn maximum_buffer_size(&self) -> usize {
        self.maximum_buffer_size
    }

    /// Maximum validated block size, including its container header/footer.
    pub const fn maximum_block_size(&self) -> usize {
        self.maximum_block_size
    }

    /// Maximum packet bytes copied into an owned record.
    pub const fn maximum_packet_bytes(&self) -> usize {
        self.maximum_packet_bytes
    }

    /// Maximum aggregate retained packet bytes for convenience collection.
    pub const fn maximum_retained_packet_bytes(&self) -> usize {
        self.maximum_retained_packet_bytes
    }

    /// Maximum accepted interfaces in each PCAPNG section.
    pub const fn maximum_interfaces_per_section(&self) -> usize {
        self.maximum_interfaces_per_section
    }

    /// Maximum accepted PCAPNG sections.
    pub const fn maximum_sections(&self) -> usize {
        self.maximum_sections
    }

    /// Maximum retained diagnostics.
    pub const fn maximum_diagnostics(&self) -> usize {
        self.maximum_diagnostics
    }

    /// Maximum emitted packet records.
    pub const fn maximum_records(&self) -> usize {
        self.maximum_records
    }

    /// Maximum processed container blocks, including skipped blocks.
    pub const fn maximum_blocks(&self) -> usize {
        self.maximum_blocks
    }

    fn validate(&self) -> Result<(), CaptureReaderError> {
        if self.initial_buffer_size == 0 || self.initial_buffer_size > MAX_ALLOWED_BUFFER_SIZE {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::InitialBufferSize,
                value: self.initial_buffer_size,
            });
        }
        if self.maximum_buffer_size < PCAPNG_EPB_MIN_SIZE
            || self.maximum_buffer_size > MAX_ALLOWED_BUFFER_SIZE
        {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::MaximumBufferSize,
                value: self.maximum_buffer_size,
            });
        }
        if self.initial_buffer_size > self.maximum_buffer_size {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::InitialBufferSize,
                value: self.initial_buffer_size,
            });
        }
        if self.maximum_block_size < PCAPNG_EPB_MIN_SIZE
            || self.maximum_block_size > MAX_ALLOWED_BLOCK_SIZE
            || self.maximum_block_size > self.maximum_buffer_size
        {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::MaximumBlockSize,
                value: self.maximum_block_size,
            });
        }
        if self.maximum_packet_bytes == 0
            || self.maximum_packet_bytes > MAX_ALLOWED_PACKET_SIZE
            || self.maximum_packet_bytes > self.maximum_block_size
        {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::MaximumPacketBytes,
                value: self.maximum_packet_bytes,
            });
        }
        if self.maximum_retained_packet_bytes == 0
            || self.maximum_retained_packet_bytes > MAX_ALLOWED_RETAINED_PACKET_BYTES
        {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::MaximumRetainedPacketBytes,
                value: self.maximum_retained_packet_bytes,
            });
        }
        if self.maximum_interfaces_per_section == 0
            || self.maximum_interfaces_per_section > MAX_ALLOWED_INTERFACES
        {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::MaximumInterfacesPerSection,
                value: self.maximum_interfaces_per_section,
            });
        }
        if self.maximum_sections == 0 || self.maximum_sections > MAX_ALLOWED_SECTIONS {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::MaximumSections,
                value: self.maximum_sections,
            });
        }
        if self.maximum_diagnostics == 0 || self.maximum_diagnostics > MAX_ALLOWED_DIAGNOSTICS {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::MaximumDiagnostics,
                value: self.maximum_diagnostics,
            });
        }
        if self.maximum_records == 0 || self.maximum_records > MAX_ALLOWED_RECORDS {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::MaximumRecords,
                value: self.maximum_records,
            });
        }
        if self.maximum_blocks == 0 || self.maximum_blocks > MAX_ALLOWED_BLOCKS {
            return Err(CaptureReaderError::InvalidLimits {
                limit: ReaderLimit::MaximumBlocks,
                value: self.maximum_blocks,
            });
        }
        Ok(())
    }
}

/// Builder for [`ReaderLimits`].  Calling [`ReaderLimitsBuilder::build`] is the
/// validation boundary; a reader never accepts an unvalidated policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaderLimitsBuilder {
    initial_buffer_size: usize,
    maximum_buffer_size: usize,
    maximum_block_size: usize,
    maximum_packet_bytes: usize,
    maximum_retained_packet_bytes: usize,
    maximum_interfaces_per_section: usize,
    maximum_sections: usize,
    maximum_diagnostics: usize,
    maximum_records: usize,
    maximum_blocks: usize,
}

impl Default for ReaderLimitsBuilder {
    fn default() -> Self {
        let limits = ReaderLimits::default();
        Self {
            initial_buffer_size: limits.initial_buffer_size,
            maximum_buffer_size: limits.maximum_buffer_size,
            maximum_block_size: limits.maximum_block_size,
            maximum_packet_bytes: limits.maximum_packet_bytes,
            maximum_retained_packet_bytes: limits.maximum_retained_packet_bytes,
            maximum_interfaces_per_section: limits.maximum_interfaces_per_section,
            maximum_sections: limits.maximum_sections,
            maximum_diagnostics: limits.maximum_diagnostics,
            maximum_records: limits.maximum_records,
            maximum_blocks: limits.maximum_blocks,
        }
    }
}

impl ReaderLimitsBuilder {
    /// Sets the initial buffer size.
    pub const fn initial_buffer_size(mut self, value: usize) -> Self {
        self.initial_buffer_size = value;
        self
    }

    /// Sets the maximum buffer size.
    pub const fn maximum_buffer_size(mut self, value: usize) -> Self {
        self.maximum_buffer_size = value;
        self
    }

    /// Sets the maximum complete block size.
    pub const fn maximum_block_size(mut self, value: usize) -> Self {
        self.maximum_block_size = value;
        self
    }

    /// Sets the maximum individual packet bytes.
    pub const fn maximum_packet_bytes(mut self, value: usize) -> Self {
        self.maximum_packet_bytes = value;
        self
    }

    /// Sets the maximum aggregate retained packet bytes for collection.
    pub const fn maximum_retained_packet_bytes(mut self, value: usize) -> Self {
        self.maximum_retained_packet_bytes = value;
        self
    }

    /// Sets the maximum interfaces per PCAPNG section.
    pub const fn maximum_interfaces_per_section(mut self, value: usize) -> Self {
        self.maximum_interfaces_per_section = value;
        self
    }

    /// Sets the maximum PCAPNG sections.
    pub const fn maximum_sections(mut self, value: usize) -> Self {
        self.maximum_sections = value;
        self
    }

    /// Sets the maximum retained diagnostics.
    pub const fn maximum_diagnostics(mut self, value: usize) -> Self {
        self.maximum_diagnostics = value;
        self
    }

    /// Sets the maximum emitted records.
    pub const fn maximum_records(mut self, value: usize) -> Self {
        self.maximum_records = value;
        self
    }

    /// Sets the maximum processed blocks.
    pub const fn maximum_blocks(mut self, value: usize) -> Self {
        self.maximum_blocks = value;
        self
    }

    /// Validates and returns the finite policy.
    pub fn build(self) -> Result<ReaderLimits, CaptureReaderError> {
        ReaderLimits::new(
            self.initial_buffer_size,
            self.maximum_buffer_size,
            self.maximum_block_size,
            self.maximum_packet_bytes,
            self.maximum_retained_packet_bytes,
            self.maximum_interfaces_per_section,
            self.maximum_sections,
            self.maximum_diagnostics,
            self.maximum_records,
            self.maximum_blocks,
        )
    }
}

/// One emitted packet record.  Ordinals are assigned only to records actually
/// returned by the reader, starting at zero, in capture order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureRecord {
    /// Zero-based emitted packet ordinal.
    pub ordinal: u64,
    /// Absolute block offset in the input stream.
    pub offset: u64,
    /// PCAPNG section ordinal, or `None` for legacy PCAP.
    pub section_ordinal: Option<u32>,
    /// PCAPNG interface ordinal, or `None` for legacy PCAP.
    pub interface_ordinal: Option<u32>,
    /// Link type associated with the packet.
    pub linktype: u32,
    /// Captured byte count represented by `packet`.
    pub captured_length: u32,
    /// Original on-wire byte count.
    pub original_length: u32,
    /// Whether the captured bytes are shorter than the original length.
    pub truncated: bool,
    /// Format-provided timestamp or explicit unavailable state.
    pub timestamp: CaptureTimestamp,
    /// Exact owned captured packet bytes without container padding.
    pub packet: CapturedPacket,
}

impl CaptureRecord {
    /// Borrows this capture record as a domain [`pcapraven_domain::PacketNormalizationInput`].
    #[must_use]
    pub fn as_normalization_input(&self) -> pcapraven_domain::PacketNormalizationInput<'_> {
        pcapraven_domain::PacketNormalizationInput {
            reference: pcapraven_domain::PacketReference {
                capture_record_ordinal: self.ordinal,
                section_ordinal: self.section_ordinal,
                interface_ordinal: self.interface_ordinal,
                captured_len: self.captured_length,
                original_len: self.original_length,
                truncated: self.truncated,
            },
            timestamp: self.timestamp.to_packet_timestamp(),
            linktype: self.linktype,
            data: self.packet.as_slice(),
        }
    }
}

impl<'a> From<&'a CaptureRecord> for pcapraven_domain::PacketNormalizationInput<'a> {
    fn from(record: &'a CaptureRecord) -> Self {
        record.as_normalization_input()
    }
}

/// Completion state for a capture read.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureCompletion {
    /// The input reached a clean end after all supported work completed.
    Complete,
    /// Useful records were produced, but recovery or a terminal error means the
    /// result must not be treated as complete.
    Partial {
        /// Terminal error, if continuation was impossible.
        terminal_error: Option<CaptureReaderError>,
    },
    /// No useful packet record was emitted before a terminal error.
    FailedBeforeUsefulRecords {
        /// The reason no useful record result exists.
        terminal_error: CaptureReaderError,
    },
}

/// Owned result of a streaming read, including explicit completion state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureReadOutcome {
    /// Capture metadata observed before termination.
    pub metadata: CaptureMetadata,
    /// Bounded emitted packet records in capture order.
    pub records: Vec<CaptureRecord>,
    /// Bounded diagnostics in deterministic production order.
    pub diagnostics: Vec<CaptureDiagnostic>,
    /// Complete, partial, or failed-before-useful-records state.
    pub completion: CaptureCompletion,
}

impl CaptureReadOutcome {
    /// Returns whether the result reached a clean end.
    pub const fn is_complete(&self) -> bool {
        matches!(self.completion, CaptureCompletion::Complete)
    }
}

/// Read a capture to completion using a generic streaming [`Read`] source.
///
/// Construction failures are represented as
/// [`CaptureCompletion::FailedBeforeUsefulRecords`] so callers cannot mistake
/// an empty vector for a successfully completed empty capture.
pub fn read_capture<'a, R: Read + Send + 'a>(
    reader: R,
    limits: ReaderLimits,
) -> CaptureReadOutcome {
    match CaptureReader::new(reader, limits) {
        Ok(reader) => reader.read_to_end(),
        Err(error) => CaptureReadOutcome {
            metadata: CaptureMetadata::unknown(),
            records: Vec::new(),
            diagnostics: vec![diagnostic_for_error(&error)],
            completion: CaptureCompletion::FailedBeforeUsefulRecords {
                terminal_error: error,
            },
        },
    }
}

/// A library-first streaming reader over either supported capture format.
pub struct CaptureReader<'a> {
    parser: Box<dyn PcapReaderIterator + Send + 'a>,
    limits: ReaderLimits,
    format: CaptureFormat,
    state: ReaderState,
    metadata: CaptureMetadata,
    diagnostics: Vec<CaptureDiagnostic>,
    buffer_size: usize,
    blocks_seen: usize,
    records_emitted: u64,
    partial: bool,
    finished: bool,
    terminal_error: Option<CaptureReaderError>,
}

impl<'a> CaptureReader<'a> {
    /// Constructs a streaming reader.  No filesystem access is performed; the
    /// caller owns the supplied [`Read`] source.
    pub fn new<R: Read + Send + 'a>(
        reader: R,
        limits: ReaderLimits,
    ) -> Result<Self, CaptureReaderError> {
        limits.validate()?;
        let (prefix, reader, format, byte_order, capacity) = prepare_prefix(reader, &limits)?;
        let prefixed_reader = PrefixReader::with_reader(prefix, reader);
        let parser = create_reader(capacity, prefixed_reader)
            .map_err(|error| map_parser_error(error, CaptureLocation::new(0), true, format))?;
        let state = match format {
            CaptureFormat::LegacyPcap => ReaderState::Legacy {
                byte_order,
                header_seen: false,
                modified: false,
            },
            CaptureFormat::PcapNg => ReaderState::PcapNg {
                byte_order,
                current_section: None,
            },
            CaptureFormat::Unknown => ReaderState::Unknown,
        };
        Ok(Self {
            parser,
            limits,
            format,
            state,
            metadata: CaptureMetadata {
                format,
                legacy: None,
                sections: Vec::new(),
            },
            diagnostics: Vec::new(),
            buffer_size: capacity,
            blocks_seen: 0,
            records_emitted: 0,
            partial: false,
            finished: false,
            terminal_error: None,
        })
    }

    /// Returns metadata accumulated so far.
    pub fn metadata(&self) -> &CaptureMetadata {
        &self.metadata
    }

    /// Returns retained diagnostics accumulated so far.
    pub fn diagnostics(&self) -> &[CaptureDiagnostic] {
        &self.diagnostics
    }

    /// Returns the number of packet records emitted so far.
    pub fn records_emitted(&self) -> u64 {
        self.records_emitted
    }

    /// Reads until the next emitted packet, clean EOF, or terminal error.
    pub fn next_record(&mut self) -> Result<Option<CaptureRecord>, CaptureReaderError> {
        if let Some(error) = &self.terminal_error {
            return Err(error.clone());
        }
        if self.finished {
            return Ok(None);
        }

        loop {
            let location = self.current_location();
            let available_data = self.parser.data().len();
            let consumed = self.parser.consumed();
            let next = self.parser.next();
            match next {
                Ok((offset, block)) => {
                    if offset == 0 || offset > available_data {
                        let error = CaptureReaderError::Internal { location };
                        return Err(self.set_terminal(error));
                    }
                    if self.blocks_seen >= self.limits.maximum_blocks {
                        let error = CaptureReaderError::ResourceLimit {
                            limit: ReaderLimit::MaximumBlocks,
                            location,
                        };
                        return Err(self.set_terminal(error));
                    }
                    self.blocks_seen += 1;
                    let view = ReaderView {
                        state: &self.state,
                        metadata: &self.metadata,
                        records_emitted: self.records_emitted,
                        limits: &self.limits,
                    };
                    let event = view.extract_block(block, location);
                    if consumed.checked_add(offset).is_none() {
                        let error = CaptureReaderError::ResourceLimit {
                            limit: ReaderLimit::MaximumBlocks,
                            location,
                        };
                        return Err(self.set_terminal(error));
                    }
                    self.parser.consume(offset);
                    match event {
                        Ok(BlockEvent::Packet(record)) => {
                            let next_emitted = match self.records_emitted.checked_add(1) {
                                Some(count) => count,
                                None => {
                                    let error = CaptureReaderError::ResourceLimit {
                                        limit: ReaderLimit::MaximumRecords,
                                        location,
                                    };
                                    return Err(self.set_terminal(error));
                                }
                            };
                            self.records_emitted = next_emitted;
                            return Ok(Some(record));
                        }
                        Ok(BlockEvent::Header(header)) => {
                            self.metadata.legacy = Some(header);
                            if let ReaderState::Legacy { header_seen, .. } = &mut self.state {
                                *header_seen = true;
                            }
                        }
                        Ok(BlockEvent::Section(section)) => {
                            let section_ordinal = section.ordinal;
                            self.metadata.sections.push(section);
                            if let ReaderState::PcapNg {
                                byte_order,
                                current_section,
                            } = &mut self.state
                            {
                                *current_section = Some(section_ordinal);
                                if let Some(last_section) = self.metadata.sections.last() {
                                    *byte_order = last_section.byte_order;
                                }
                            }
                        }
                        Ok(BlockEvent::Interface {
                            section,
                            slot,
                            diagnostic,
                        }) => {
                            let section_index = match usize::try_from(section) {
                                Ok(index) => index,
                                Err(_) => {
                                    let error = CaptureReaderError::Internal { location };
                                    return Err(self.set_terminal(error));
                                }
                            };
                            if let Some(capture_section) =
                                self.metadata.sections.get_mut(section_index)
                            {
                                capture_section.interfaces.push(slot);
                            } else {
                                let error = CaptureReaderError::Internal { location };
                                return Err(self.set_terminal(error));
                            }
                            if let Some(diag) = diagnostic {
                                self.partial = true;
                                if let Err(error) = self.push_diagnostic(diag) {
                                    return Err(self.set_terminal(error));
                                }
                            }
                        }
                        Ok(BlockEvent::Diagnostic {
                            diagnostic,
                            partial,
                        }) => {
                            if partial {
                                self.partial = true;
                            }
                            if let Err(error) = self.push_diagnostic(diagnostic) {
                                return Err(self.set_terminal(error));
                            }
                        }
                        Err(error) => return Err(self.set_terminal(error)),
                    }
                }
                Err(PcapError::Eof) => {
                    self.finished = true;
                    return Ok(None);
                }
                Err(PcapError::Incomplete(_)) | Err(PcapError::BufferTooSmall) => {
                    if let Err(error) = self.handle_incomplete(location) {
                        return Err(self.set_terminal(error));
                    }
                }
                Err(error) => {
                    let error = map_parser_error(error, location, false, self.format);
                    return Err(self.set_terminal(error));
                }
            }
        }
    }

    /// Consumes the reader and reads until a clean end or terminal error,
    /// collecting emitted records up to the configured aggregate retention limit.
    pub fn read_to_end(mut self) -> CaptureReadOutcome {
        let mut records = Vec::new();
        let mut retained_packet_bytes: usize = 0;
        loop {
            match self.next_record() {
                Ok(Some(record)) => {
                    let packet_len = record.packet.len();
                    let next_retained = match retained_packet_bytes.checked_add(packet_len) {
                        Some(sum) => sum,
                        None => {
                            let error = CaptureReaderError::ResourceLimit {
                                limit: ReaderLimit::MaximumRetainedPacketBytes,
                                location: CaptureLocation::new(record.offset),
                            };
                            self.set_terminal(error);
                            break;
                        }
                    };
                    if next_retained > self.limits.maximum_retained_packet_bytes {
                        let error = CaptureReaderError::ResourceLimit {
                            limit: ReaderLimit::MaximumRetainedPacketBytes,
                            location: CaptureLocation::new(record.offset),
                        };
                        self.set_terminal(error);
                        break;
                    }
                    retained_packet_bytes = next_retained;
                    records.push(record);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        self.into_outcome_with_records(records)
    }

    fn into_outcome_with_records(self, records: Vec<CaptureRecord>) -> CaptureReadOutcome {
        let completion = match self.terminal_error.clone() {
            Some(error) if records.is_empty() => CaptureCompletion::FailedBeforeUsefulRecords {
                terminal_error: error,
            },
            Some(error) => CaptureCompletion::Partial {
                terminal_error: Some(error),
            },
            None if self.partial => CaptureCompletion::Partial {
                terminal_error: None,
            },
            None => CaptureCompletion::Complete,
        };
        CaptureReadOutcome {
            metadata: self.metadata,
            records,
            diagnostics: self.diagnostics,
            completion,
        }
    }

    /// Consumes the reader and returns the state observed so far with no collected records.
    pub fn into_outcome(self) -> CaptureReadOutcome {
        self.into_outcome_with_records(Vec::new())
    }

    fn current_location(&self) -> CaptureLocation {
        let offset = u64::try_from(self.parser.consumed()).unwrap_or(u64::MAX);
        let mut location = CaptureLocation::new(offset);
        match self.state {
            ReaderState::Legacy { .. } | ReaderState::Unknown => {}
            ReaderState::PcapNg {
                current_section, ..
            } => location.section_ordinal = current_section,
        }
        location
    }
}

struct ReaderView<'a> {
    state: &'a ReaderState,
    metadata: &'a CaptureMetadata,
    records_emitted: u64,
    limits: &'a ReaderLimits,
}

impl ReaderView<'_> {
    fn extract_block(
        &self,
        block: PcapBlockOwned<'_>,
        location: CaptureLocation,
    ) -> Result<BlockEvent, CaptureReaderError> {
        match block {
            PcapBlockOwned::LegacyHeader(header) => {
                let byte_order = if header.is_bigendian() {
                    ByteOrder::Big
                } else {
                    ByteOrder::Little
                };
                if header.is_modified_format() {
                    return Err(CaptureReaderError::Unsupported {
                        detail: UnsupportedCapture::ModifiedPcap,
                        location,
                    });
                }
                if header.version_major != 2 || header.version_minor != 4 {
                    return Err(CaptureReaderError::Unsupported {
                        detail: UnsupportedCapture::LegacyVersion,
                        location,
                    });
                }
                let linktype =
                    u32::try_from(header.network.0).map_err(|_| CaptureReaderError::Malformed {
                        detail: MalformedCapture::Header,
                        location,
                    })?;
                let resolution = if header.is_nanosecond_precision() {
                    decimal_resolution(9)
                } else {
                    decimal_resolution(6)
                }
                .ok_or(CaptureReaderError::Malformed {
                    detail: MalformedCapture::Timestamp,
                    location,
                })?;
                Ok(BlockEvent::Header(CaptureGlobalMetadata {
                    byte_order,
                    version_major: header.version_major,
                    version_minor: header.version_minor,
                    timestamp_offset_seconds: header.thiszone,
                    sigfigs: header.sigfigs,
                    snaplen: header.snaplen,
                    linktype,
                    timestamp_resolution: resolution,
                }))
            }
            PcapBlockOwned::Legacy(packet) => {
                let (byte_order, header) = match *self.state {
                    ReaderState::Legacy {
                        byte_order,
                        header_seen: _,
                        modified: _,
                    } => (byte_order, self.metadata.legacy.as_ref()),
                    _ => {
                        return Err(CaptureReaderError::Internal { location });
                    }
                };
                let header = header.ok_or(CaptureReaderError::Internal { location })?;
                let captured_length = usize::try_from(packet.caplen).map_err(|_| {
                    CaptureReaderError::ResourceLimit {
                        limit: ReaderLimit::MaximumPacketBytes,
                        location,
                    }
                })?;
                if captured_length > self.limits.maximum_packet_bytes {
                    return Err(CaptureReaderError::ResourceLimit {
                        limit: ReaderLimit::MaximumPacketBytes,
                        location,
                    });
                }
                if header.snaplen != 0 && packet.caplen > header.snaplen {
                    return Ok(BlockEvent::Diagnostic {
                        diagnostic: diagnostic(
                            CaptureDiagnosticKind::Malformed,
                            CaptureDiagnosticStage::Packet,
                            "legacy captured length exceeds snap length",
                            location,
                            true,
                        ),
                        partial: true,
                    });
                }
                if packet.origlen < packet.caplen {
                    return Ok(BlockEvent::Diagnostic {
                        diagnostic: diagnostic(
                            CaptureDiagnosticKind::Malformed,
                            CaptureDiagnosticStage::Packet,
                            "legacy original length is shorter than captured length",
                            location,
                            true,
                        ),
                        partial: true,
                    });
                }
                let timestamp = CaptureTimestamp::available(
                    i128::from(packet.ts_sec),
                    u64::from(packet.ts_usec),
                    header.timestamp_resolution,
                    i64::from(header.timestamp_offset_seconds),
                )
                .ok_or(CaptureReaderError::Malformed {
                    detail: MalformedCapture::Timestamp,
                    location,
                })?;
                if packet.data.len() != captured_length {
                    return Err(CaptureReaderError::Malformed {
                        detail: MalformedCapture::Boundary,
                        location,
                    });
                }
                let ordinal = self.records_emitted;
                if usize::try_from(ordinal)
                    .map_or(true, |count| count >= self.limits.maximum_records)
                {
                    return Err(CaptureReaderError::ResourceLimit {
                        limit: ReaderLimit::MaximumRecords,
                        location,
                    });
                }
                let _ = byte_order;
                Ok(BlockEvent::Packet(CaptureRecord {
                    ordinal,
                    offset: location.offset,
                    section_ordinal: None,
                    interface_ordinal: None,
                    linktype: header.linktype,
                    captured_length: packet.caplen,
                    original_length: packet.origlen,
                    truncated: packet.origlen > packet.caplen,
                    timestamp,
                    packet: CapturedPacket::from_borrowed(packet.data),
                }))
            }
            PcapBlockOwned::NG(block) => self.extract_ng_block(block, location),
        }
    }

    fn extract_ng_block(
        &self,
        block: Block<'_>,
        mut location: CaptureLocation,
    ) -> Result<BlockEvent, CaptureReaderError> {
        let section_ordinal = match *self.state {
            ReaderState::PcapNg {
                current_section, ..
            } => current_section,
            _ => None,
        };
        location.section_ordinal = section_ordinal;
        match block {
            Block::SectionHeader(header) => {
                location.block_type = Some(SHB_MAGIC);
                let byte_order = if header.big_endian() {
                    ByteOrder::Big
                } else {
                    ByteOrder::Little
                };
                if header.major_version != 1 || header.minor_version != 0 {
                    return Err(CaptureReaderError::Unsupported {
                        detail: UnsupportedCapture::PcapNgVersion,
                        location,
                    });
                }
                if self.metadata.sections.len() >= self.limits.maximum_sections {
                    return Err(CaptureReaderError::ResourceLimit {
                        limit: ReaderLimit::MaximumSections,
                        location,
                    });
                }
                let ordinal = u32::try_from(self.metadata.sections.len()).map_err(|_| {
                    CaptureReaderError::ResourceLimit {
                        limit: ReaderLimit::MaximumSections,
                        location,
                    }
                })?;
                Ok(BlockEvent::Section(CaptureSection {
                    ordinal,
                    byte_order,
                    version_major: header.major_version,
                    version_minor: header.minor_version,
                    section_length: header.section_len,
                    interfaces: Vec::new(),
                }))
            }
            Block::InterfaceDescription(interface) => {
                location.block_type = Some(IDB_MAGIC);
                let section =
                    section_ordinal.ok_or(CaptureReaderError::InvalidReference { location })?;
                let section_data = self
                    .metadata
                    .sections
                    .get(
                        usize::try_from(section)
                            .map_err(|_| CaptureReaderError::Internal { location })?,
                    )
                    .ok_or(CaptureReaderError::Internal { location })?;
                if section_data.interfaces.len() >= self.limits.maximum_interfaces_per_section {
                    return Err(CaptureReaderError::ResourceLimit {
                        limit: ReaderLimit::MaximumInterfacesPerSection,
                        location,
                    });
                }
                let interface_ordinal =
                    u32::try_from(section_data.interfaces.len()).map_err(|_| {
                        CaptureReaderError::ResourceLimit {
                            limit: ReaderLimit::MaximumInterfacesPerSection,
                            location,
                        }
                    })?;
                location.interface_ordinal = Some(interface_ordinal);

                let linktype = match u32::try_from(interface.linktype.0) {
                    Ok(linktype) => linktype,
                    Err(_) => {
                        return Ok(BlockEvent::Interface {
                            section,
                            slot: CaptureInterfaceSlot::Unusable {
                                section_ordinal: section,
                                interface_ordinal,
                            },
                            diagnostic: Some(diagnostic(
                                CaptureDiagnosticKind::Malformed,
                                CaptureDiagnosticStage::Interface,
                                "interface link type is not representable",
                                location,
                                true,
                            )),
                        });
                    }
                };
                let byte_order = match *self.state {
                    ReaderState::PcapNg { byte_order, .. } => byte_order,
                    _ => return Err(CaptureReaderError::Internal { location }),
                };
                let (raw_resolution, timestamp_offset_seconds) =
                    match interface_timestamp_options(&interface.options, byte_order) {
                        Ok(options) => options,
                        Err(()) => {
                            return Ok(BlockEvent::Interface {
                                section,
                                slot: CaptureInterfaceSlot::Unusable {
                                    section_ordinal: section,
                                    interface_ordinal,
                                },
                                diagnostic: Some(diagnostic(
                                    CaptureDiagnosticKind::Malformed,
                                    CaptureDiagnosticStage::Interface,
                                    "interface timestamp option is malformed",
                                    location,
                                    true,
                                )),
                            });
                        }
                    };
                let timestamp_resolution = match timestamp_resolution(raw_resolution) {
                    Some(resolution) => resolution,
                    None => {
                        return Ok(BlockEvent::Interface {
                            section,
                            slot: CaptureInterfaceSlot::Unusable {
                                section_ordinal: section,
                                interface_ordinal,
                            },
                            diagnostic: Some(diagnostic(
                                CaptureDiagnosticKind::Malformed,
                                CaptureDiagnosticStage::Interface,
                                "interface timestamp resolution is unsupported",
                                location,
                                true,
                            )),
                        });
                    }
                };
                Ok(BlockEvent::Interface {
                    section,
                    slot: CaptureInterfaceSlot::Valid(CaptureInterface {
                        section_ordinal: section,
                        interface_ordinal,
                        linktype,
                        snaplen: interface.snaplen,
                        byte_order,
                        timestamp_resolution,
                        timestamp_offset_seconds,
                    }),
                    diagnostic: None,
                })
            }
            Block::EnhancedPacket(packet) => {
                let interface_ordinal = packet.if_id;
                location.interface_ordinal = Some(interface_ordinal);
                location.block_type = Some(EPB_MAGIC);
                let section =
                    section_ordinal.ok_or(CaptureReaderError::InvalidReference { location })?;
                let interface = match self.interface(section, interface_ordinal, location) {
                    Ok(interface) => interface,
                    Err(_) => {
                        return Ok(BlockEvent::Diagnostic {
                            diagnostic: diagnostic(
                                CaptureDiagnosticKind::InvalidReference,
                                CaptureDiagnosticStage::Packet,
                                "enhanced packet references an unavailable interface",
                                location,
                                true,
                            ),
                            partial: true,
                        });
                    }
                };
                let captured = packet.packet_data();
                let captured_length = u32::try_from(captured.len()).map_err(|_| {
                    CaptureReaderError::ResourceLimit {
                        limit: ReaderLimit::MaximumPacketBytes,
                        location,
                    }
                })?;
                if let Err(error) = self.validate_packet_lengths(
                    captured_length,
                    packet.origlen,
                    interface.snaplen,
                    location,
                ) {
                    if error.kind() != CaptureReaderErrorKind::Malformed {
                        return Err(error);
                    }
                    return Ok(BlockEvent::Diagnostic {
                        diagnostic: diagnostic(
                            CaptureDiagnosticKind::Malformed,
                            CaptureDiagnosticStage::Packet,
                            packet_length_message(&error),
                            location,
                            true,
                        ),
                        partial: true,
                    });
                }
                let timestamp = self.ng_timestamp(
                    (u64::from(packet.ts_high) << 32) | u64::from(packet.ts_low),
                    interface.timestamp_resolution,
                    interface.timestamp_offset_seconds,
                    location,
                )?;
                self.packet_event(
                    location,
                    section,
                    interface_ordinal,
                    interface.linktype,
                    captured_length,
                    packet.origlen,
                    timestamp,
                    captured,
                )
            }
            Block::SimplePacket(packet) => {
                location.block_type = Some(SPB_MAGIC);
                let section =
                    section_ordinal.ok_or(CaptureReaderError::InvalidReference { location })?;
                let interface = match self.interface(section, 0, {
                    let mut interface_location = location;
                    interface_location.interface_ordinal = Some(0);
                    interface_location
                }) {
                    Ok(interface) => interface,
                    Err(_) => {
                        return Ok(BlockEvent::Diagnostic {
                            diagnostic: diagnostic(
                                CaptureDiagnosticKind::InvalidReference,
                                CaptureDiagnosticStage::Packet,
                                "simple packet has no section-local interface zero",
                                location,
                                true,
                            ),
                            partial: true,
                        });
                    }
                };
                location.interface_ordinal = Some(0);
                let captured = packet.packet_data();
                let captured_length = u32::try_from(captured.len()).map_err(|_| {
                    CaptureReaderError::ResourceLimit {
                        limit: ReaderLimit::MaximumPacketBytes,
                        location,
                    }
                })?;
                if let Err(error) = self.validate_packet_lengths(
                    captured_length,
                    packet.origlen,
                    interface.snaplen,
                    location,
                ) {
                    if error.kind() != CaptureReaderErrorKind::Malformed {
                        return Err(error);
                    }
                    return Ok(BlockEvent::Diagnostic {
                        diagnostic: diagnostic(
                            CaptureDiagnosticKind::Malformed,
                            CaptureDiagnosticStage::Packet,
                            packet_length_message(&error),
                            location,
                            true,
                        ),
                        partial: true,
                    });
                }
                self.packet_event(
                    location,
                    section,
                    0,
                    interface.linktype,
                    captured_length,
                    packet.origlen,
                    CaptureTimestamp::Unavailable,
                    captured,
                )
            }
            Block::Unknown(unknown) => {
                location.block_type = Some(unknown.block_type);
                Ok(BlockEvent::Diagnostic {
                    diagnostic: diagnostic(
                        CaptureDiagnosticKind::Unsupported,
                        CaptureDiagnosticStage::Block,
                        "valid PCAPNG block is outside the supported subset",
                        location,
                        true,
                    ),
                    partial: false,
                })
            }
            other => {
                location.block_type = Some(other.magic());
                Ok(BlockEvent::Diagnostic {
                    diagnostic: diagnostic(
                        CaptureDiagnosticKind::Unsupported,
                        CaptureDiagnosticStage::Block,
                        "valid PCAPNG block is outside the supported subset",
                        location,
                        true,
                    ),
                    partial: false,
                })
            }
        }
    }

    fn interface(
        &self,
        section: u32,
        interface: u32,
        mut location: CaptureLocation,
    ) -> Result<&CaptureInterface, CaptureReaderError> {
        location.section_ordinal = Some(section);
        location.interface_ordinal = Some(interface);
        let section = self
            .metadata
            .sections
            .get(
                usize::try_from(section)
                    .map_err(|_| CaptureReaderError::InvalidReference { location })?,
            )
            .ok_or(CaptureReaderError::InvalidReference { location })?;
        let slot = section
            .interfaces
            .get(
                usize::try_from(interface)
                    .map_err(|_| CaptureReaderError::InvalidReference { location })?,
            )
            .ok_or(CaptureReaderError::InvalidReference { location })?;
        slot.as_valid()
            .ok_or(CaptureReaderError::InvalidReference { location })
    }

    fn validate_packet_lengths(
        &self,
        captured_length: u32,
        original_length: u32,
        snaplen: u32,
        location: CaptureLocation,
    ) -> Result<(), CaptureReaderError> {
        if usize::try_from(captured_length).map_err(|_| CaptureReaderError::ResourceLimit {
            limit: ReaderLimit::MaximumPacketBytes,
            location,
        })? > self.limits.maximum_packet_bytes
        {
            return Err(CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumPacketBytes,
                location,
            });
        }
        if snaplen != 0 && captured_length > snaplen {
            return Err(CaptureReaderError::Malformed {
                detail: MalformedCapture::LengthMismatch,
                location,
            });
        }
        if original_length < captured_length {
            return Err(CaptureReaderError::Malformed {
                detail: MalformedCapture::LengthMismatch,
                location,
            });
        }
        Ok(())
    }

    fn ng_timestamp(
        &self,
        raw: u64,
        resolution: CaptureTimestampResolution,
        offset_seconds: i64,
        location: CaptureLocation,
    ) -> Result<CaptureTimestamp, CaptureReaderError> {
        let units = resolution.units_per_second();
        let seconds = i128::from(raw / units);
        let fractional_units = raw % units;
        CaptureTimestamp::available(seconds, fractional_units, resolution, offset_seconds).ok_or(
            CaptureReaderError::Malformed {
                detail: MalformedCapture::Timestamp,
                location,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn packet_event(
        &self,
        location: CaptureLocation,
        section: u32,
        interface: u32,
        linktype: u32,
        captured_length: u32,
        original_length: u32,
        timestamp: CaptureTimestamp,
        captured: &[u8],
    ) -> Result<BlockEvent, CaptureReaderError> {
        let ordinal = self.records_emitted;
        if usize::try_from(ordinal).map_or(true, |count| count >= self.limits.maximum_records) {
            return Err(CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumRecords,
                location,
            });
        }
        if captured.len()
            != usize::try_from(captured_length).map_err(|_| CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumPacketBytes,
                location,
            })?
        {
            return Err(CaptureReaderError::Malformed {
                detail: MalformedCapture::Boundary,
                location,
            });
        }
        Ok(BlockEvent::Packet(CaptureRecord {
            ordinal,
            offset: location.offset,
            section_ordinal: Some(section),
            interface_ordinal: Some(interface),
            linktype,
            captured_length,
            original_length,
            truncated: original_length > captured_length,
            timestamp,
            packet: CapturedPacket::from_borrowed(captured),
        }))
    }
}

impl<'a> CaptureReader<'a> {
    fn push_diagnostic(&mut self, diagnostic: CaptureDiagnostic) -> Result<(), CaptureReaderError> {
        if self.diagnostics.len() >= self.limits.maximum_diagnostics {
            return Err(CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumDiagnostics,
                location: diagnostic.location,
            });
        }
        self.diagnostics.push(diagnostic);
        Ok(())
    }

    fn set_terminal(&mut self, error: CaptureReaderError) -> CaptureReaderError {
        self.partial = true;
        if self.terminal_error.is_none() {
            if self.diagnostics.len() < self.limits.maximum_diagnostics {
                self.diagnostics.push(diagnostic_for_error(&error));
            }
            self.terminal_error = Some(error.clone());
        }
        error
    }

    fn handle_incomplete(&mut self, location: CaptureLocation) -> Result<(), CaptureReaderError> {
        let (plan, data_len, buffer_size, exhausted) = {
            let data = self.parser.data();
            (
                preflight(&self.state, data, &self.limits, location)?,
                data.len(),
                self.buffer_size,
                self.parser.reader_exhausted(),
            )
        };
        let required = match plan {
            Preflight::Ready { block_size, .. } => {
                if data_len >= block_size {
                    return Err(CaptureReaderError::Malformed {
                        detail: MalformedCapture::Parser,
                        location,
                    });
                }
                block_size
            }
            Preflight::Need(required) => required,
        };
        if required > self.limits.maximum_block_size || required > self.limits.maximum_buffer_size {
            return Err(CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumBlockSize,
                location,
            });
        }
        if required > buffer_size || data_len >= buffer_size {
            self.grow_buffer(required, location)?;
        }
        let before = self.parser.data().len();
        if exhausted {
            if data_len == 0 {
                return Ok(());
            }
            return Err(CaptureReaderError::Incomplete { location });
        }
        self.parser
            .refill()
            .map_err(|error| map_parser_error(error, location, false, self.format))?;
        let after = self.parser.data().len();
        if after <= before && self.parser.reader_exhausted() {
            if after == 0 {
                return Ok(());
            }
            return Err(CaptureReaderError::Incomplete { location });
        }
        if after == before {
            return Err(CaptureReaderError::Internal { location });
        }
        Ok(())
    }

    fn grow_buffer(
        &mut self,
        required: usize,
        location: CaptureLocation,
    ) -> Result<(), CaptureReaderError> {
        let doubled = self
            .buffer_size
            .checked_mul(2)
            .ok_or(CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumBufferSize,
                location,
            })?;
        let mut target = doubled.max(required);
        if target > self.limits.maximum_buffer_size {
            target = self.limits.maximum_buffer_size;
        }
        if target <= self.buffer_size {
            return Err(CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumBufferSize,
                location,
            });
        }
        if !self.parser.grow(target) {
            return Err(CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumBufferSize,
                location,
            });
        }
        self.buffer_size = target;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
enum ReaderState {
    Unknown,
    Legacy {
        byte_order: ByteOrder,
        header_seen: bool,
        modified: bool,
    },
    PcapNg {
        byte_order: ByteOrder,
        current_section: Option<u32>,
    },
}

enum BlockEvent {
    Header(CaptureGlobalMetadata),
    Section(CaptureSection),
    Interface {
        section: u32,
        slot: CaptureInterfaceSlot,
        diagnostic: Option<CaptureDiagnostic>,
    },
    Packet(CaptureRecord),
    Diagnostic {
        diagnostic: CaptureDiagnostic,
        partial: bool,
    },
}

enum Preflight {
    Need(usize),
    Ready { block_size: usize },
}

fn diagnostic(
    kind: CaptureDiagnosticKind,
    stage: CaptureDiagnosticStage,
    message: &'static str,
    location: CaptureLocation,
    recovered: bool,
) -> CaptureDiagnostic {
    CaptureDiagnostic {
        kind,
        stage,
        message,
        location,
        recovered,
    }
}

fn diagnostic_for_error(error: &CaptureReaderError) -> CaptureDiagnostic {
    let (kind, stage, message) = match error.kind() {
        CaptureReaderErrorKind::InvalidLimits => (
            CaptureDiagnosticKind::ResourceLimit,
            CaptureDiagnosticStage::Reader,
            "reader limits were invalid",
        ),
        CaptureReaderErrorKind::UnrecognizedFormat => (
            CaptureDiagnosticKind::Unsupported,
            CaptureDiagnosticStage::Format,
            "capture format was not recognized",
        ),
        CaptureReaderErrorKind::Unsupported => (
            CaptureDiagnosticKind::Unsupported,
            CaptureDiagnosticStage::Header,
            "capture variant is outside the supported subset",
        ),
        CaptureReaderErrorKind::Malformed => (
            CaptureDiagnosticKind::Malformed,
            CaptureDiagnosticStage::Block,
            "capture structure was malformed",
        ),
        CaptureReaderErrorKind::Incomplete => (
            CaptureDiagnosticKind::Incomplete,
            CaptureDiagnosticStage::Reader,
            "capture ended before a complete unit was available",
        ),
        CaptureReaderErrorKind::Io => (
            CaptureDiagnosticKind::Io,
            CaptureDiagnosticStage::Reader,
            "capture input returned an I/O error",
        ),
        CaptureReaderErrorKind::ResourceLimit => (
            CaptureDiagnosticKind::ResourceLimit,
            CaptureDiagnosticStage::Reader,
            "configured reader limit prevented continuation",
        ),
        CaptureReaderErrorKind::InvalidReference => (
            CaptureDiagnosticKind::InvalidReference,
            CaptureDiagnosticStage::Packet,
            "packet referenced unavailable section-local state",
        ),
        CaptureReaderErrorKind::Internal => (
            CaptureDiagnosticKind::Internal,
            CaptureDiagnosticStage::Reader,
            "reader invariant prevented safe continuation",
        ),
    };
    diagnostic(kind, stage, message, error.location(), false)
}

fn packet_length_message(error: &CaptureReaderError) -> &'static str {
    match error {
        CaptureReaderError::Malformed {
            detail: MalformedCapture::LengthMismatch,
            ..
        } => "packet lengths contradict interface or container limits",
        _ => "packet length is malformed",
    }
}

fn decimal_resolution(exponent: u8) -> Option<CaptureTimestampResolution> {
    if exponent > 19 {
        return None;
    }
    let units_per_second = 10u64.checked_pow(u32::from(exponent))?;
    Some(CaptureTimestampResolution::Decimal {
        exponent,
        units_per_second,
    })
}

fn timestamp_resolution(raw: u8) -> Option<CaptureTimestampResolution> {
    if raw & 0x80 == 0 {
        decimal_resolution(raw)
    } else {
        let exponent = raw & 0x7f;
        if exponent > 63 {
            return None;
        }
        let units_per_second = 1u64.checked_shl(u32::from(exponent))?;
        Some(CaptureTimestampResolution::Binary {
            exponent,
            units_per_second,
        })
    }
}

fn interface_timestamp_options(
    options: &[pcap_parser::PcapNGOption<'_>],
    byte_order: ByteOrder,
) -> Result<(u8, i64), ()> {
    let mut raw_resolution = 6u8;
    let mut timestamp_offset_seconds = 0i64;
    let mut resolution_seen = false;
    let mut offset_seen = false;
    for option in options {
        match option.code.0 {
            value if value == OptionCode::IfTsresol.0 => {
                if option.len != 1 || option.value.is_empty() {
                    return Err(());
                }
                if !resolution_seen {
                    raw_resolution = option.value[0];
                    resolution_seen = true;
                }
            }
            value if value == OptionCode::IfTsoffset.0 => {
                if option.len != 8 || option.value.len() < 8 {
                    return Err(());
                }
                let bytes: [u8; 8] = option.value[..8].try_into().map_err(|_| ())?;
                if !offset_seen {
                    timestamp_offset_seconds = byte_order.read_i64(bytes);
                    offset_seen = true;
                }
            }
            _ => {}
        }
    }
    Ok((raw_resolution, timestamp_offset_seconds))
}

fn read_bytes<const N: usize>(data: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    data.get(offset..end)?.try_into().ok()
}

fn read_u32(data: &[u8], offset: usize, byte_order: ByteOrder) -> Option<u32> {
    Some(byte_order.read_u32(read_bytes(data, offset)?))
}

fn preflight(
    state: &ReaderState,
    data: &[u8],
    limits: &ReaderLimits,
    location: CaptureLocation,
) -> Result<Preflight, CaptureReaderError> {
    match *state {
        ReaderState::Legacy {
            header_seen,
            byte_order,
            modified,
        } => {
            if !header_seen {
                return Ok(Preflight::Need(PCAP_HEADER_SIZE));
            }
            let header_size = if modified { 24 } else { 16 };
            if data.len() < header_size {
                return Ok(Preflight::Need(header_size));
            }
            let captured = read_u32(data, 8, byte_order).ok_or(CaptureReaderError::Malformed {
                detail: MalformedCapture::Boundary,
                location,
            })?;
            let captured =
                usize::try_from(captured).map_err(|_| CaptureReaderError::ResourceLimit {
                    limit: ReaderLimit::MaximumBlockSize,
                    location,
                })?;
            if captured > limits.maximum_packet_bytes {
                return Err(CaptureReaderError::ResourceLimit {
                    limit: ReaderLimit::MaximumPacketBytes,
                    location,
                });
            }
            let block_size =
                header_size
                    .checked_add(captured)
                    .ok_or(CaptureReaderError::ResourceLimit {
                        limit: ReaderLimit::MaximumBlockSize,
                        location,
                    })?;
            if block_size > limits.maximum_block_size {
                return Err(CaptureReaderError::ResourceLimit {
                    limit: ReaderLimit::MaximumBlockSize,
                    location,
                });
            }
            if data.len() < block_size {
                Ok(Preflight::Need(block_size))
            } else {
                Ok(Preflight::Ready { block_size })
            }
        }
        ReaderState::PcapNg {
            byte_order,
            current_section: _,
        } => preflight_ng(data, byte_order, limits, location),
        ReaderState::Unknown => Err(CaptureReaderError::Internal { location }),
    }
}

fn preflight_ng(
    data: &[u8],
    current_byte_order: ByteOrder,
    limits: &ReaderLimits,
    mut location: CaptureLocation,
) -> Result<Preflight, CaptureReaderError> {
    if data.len() < 8 {
        return Ok(Preflight::Need(8));
    }
    let is_shb = data.get(..4) == Some(SHB_MAGIC_BYTES.as_slice());
    let byte_order = if is_shb {
        if data.len() < 12 {
            return Ok(Preflight::Need(12));
        }
        match data.get(8..12) {
            Some([0x4d, 0x3c, 0x2b, 0x1a]) => ByteOrder::Little,
            Some([0x1a, 0x2b, 0x3c, 0x4d]) => ByteOrder::Big,
            _ => {
                return Err(CaptureReaderError::Malformed {
                    detail: MalformedCapture::Header,
                    location,
                });
            }
        }
    } else {
        current_byte_order
    };
    let block_type = if is_shb {
        SHB_MAGIC
    } else {
        read_u32(data, 0, byte_order).ok_or(CaptureReaderError::Malformed {
            detail: MalformedCapture::Boundary,
            location,
        })?
    };
    location.block_type = Some(block_type);
    let block_size_u32 = read_u32(data, 4, byte_order).ok_or(CaptureReaderError::Malformed {
        detail: MalformedCapture::Boundary,
        location,
    })?;
    let block_size =
        usize::try_from(block_size_u32).map_err(|_| CaptureReaderError::ResourceLimit {
            limit: ReaderLimit::MaximumBlockSize,
            location,
        })?;
    let minimum = match block_type {
        SHB_MAGIC => PCAPNG_SHB_MIN_SIZE,
        IDB_MAGIC => PCAPNG_IDB_MIN_SIZE,
        EPB_MAGIC => PCAPNG_EPB_MIN_SIZE,
        SPB_MAGIC => PCAPNG_SPB_MIN_SIZE,
        _ => PCAPNG_BLOCK_HEADER_SIZE,
    };
    if block_size < minimum || block_size % 4 != 0 {
        return Err(CaptureReaderError::Malformed {
            detail: MalformedCapture::Boundary,
            location,
        });
    }
    if block_size > limits.maximum_block_size {
        return Err(CaptureReaderError::ResourceLimit {
            limit: ReaderLimit::MaximumBlockSize,
            location,
        });
    }
    if data.len() < block_size {
        return Ok(Preflight::Need(block_size));
    }
    let footer =
        read_u32(data, block_size - 4, byte_order).ok_or(CaptureReaderError::Malformed {
            detail: MalformedCapture::Boundary,
            location,
        })?;
    if footer != block_size_u32 {
        return Err(CaptureReaderError::Malformed {
            detail: MalformedCapture::Boundary,
            location,
        });
    }
    if block_type == EPB_MAGIC {
        let captured = read_u32(data, 20, byte_order).ok_or(CaptureReaderError::Malformed {
            detail: MalformedCapture::Boundary,
            location,
        })?;
        let captured =
            usize::try_from(captured).map_err(|_| CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumPacketBytes,
                location,
            })?;
        if captured > limits.maximum_packet_bytes {
            return Err(CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumPacketBytes,
                location,
            });
        }
        let padded = captured.checked_add(3).map(|value| value & !3).ok_or(
            CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumBlockSize,
                location,
            },
        )?;
        let minimum_with_packet =
            PCAPNG_EPB_MIN_SIZE
                .checked_add(padded)
                .ok_or(CaptureReaderError::ResourceLimit {
                    limit: ReaderLimit::MaximumBlockSize,
                    location,
                })?;
        if block_size < minimum_with_packet {
            return Err(CaptureReaderError::Malformed {
                detail: MalformedCapture::Boundary,
                location,
            });
        }
    } else if block_type == SPB_MAGIC {
        let original = read_u32(data, 12, byte_order).ok_or(CaptureReaderError::Malformed {
            detail: MalformedCapture::Boundary,
            location,
        })?;
        let data_len =
            block_size
                .checked_sub(PCAPNG_SPB_MIN_SIZE)
                .ok_or(CaptureReaderError::Malformed {
                    detail: MalformedCapture::Boundary,
                    location,
                })?;
        let captured = usize::try_from(original)
            .ok()
            .map_or(data_len, |original| original.min(data_len));
        if captured > limits.maximum_packet_bytes {
            return Err(CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumPacketBytes,
                location,
            });
        }
    }
    Ok(Preflight::Ready { block_size })
}

fn map_parser_error(
    error: PcapError<&[u8]>,
    location: CaptureLocation,
    initializing: bool,
    format: CaptureFormat,
) -> CaptureReaderError {
    match error {
        PcapError::Eof | PcapError::UnexpectedEof | PcapError::Incomplete(_) => {
            CaptureReaderError::Incomplete { location }
        }
        PcapError::HeaderNotRecognized => {
            if initializing {
                CaptureReaderError::UnrecognizedFormat { location }
            } else {
                CaptureReaderError::Malformed {
                    detail: MalformedCapture::Parser,
                    location,
                }
            }
        }
        PcapError::BufferTooSmall => CaptureReaderError::ResourceLimit {
            limit: ReaderLimit::MaximumBufferSize,
            location,
        },
        PcapError::ReadError => CaptureReaderError::Io {
            kind: io::ErrorKind::Other,
            location,
        },
        PcapError::NomError(_, _) | PcapError::OwnedNomError(_, _) => {
            let _ = format;
            CaptureReaderError::Malformed {
                detail: MalformedCapture::Parser,
                location,
            }
        }
    }
}

fn prepare_prefix<R: Read>(
    mut reader: R,
    limits: &ReaderLimits,
) -> Result<(Vec<u8>, R, CaptureFormat, ByteOrder, usize), CaptureReaderError> {
    let mut prefix = Vec::with_capacity(INITIAL_PROBE_SIZE);
    read_up_to(&mut reader, &mut prefix, INITIAL_PROBE_SIZE)?;
    let first_four = prefix.get(..4);
    if first_four == Some(SHB_MAGIC_BYTES.as_slice()) {
        if prefix.len() < 12 {
            return Err(CaptureReaderError::Incomplete {
                location: CaptureLocation::new(0),
            });
        }
        let byte_order = match prefix.get(8..12) {
            Some([0x4d, 0x3c, 0x2b, 0x1a]) => ByteOrder::Little,
            Some([0x1a, 0x2b, 0x3c, 0x4d]) => ByteOrder::Big,
            _ => {
                return Err(CaptureReaderError::Malformed {
                    detail: MalformedCapture::Header,
                    location: CaptureLocation::new(0),
                });
            }
        };
        let block_size = read_u32(&prefix, 4, byte_order)
            .and_then(|value| usize::try_from(value).ok())
            .ok_or(CaptureReaderError::Malformed {
                detail: MalformedCapture::Boundary,
                location: CaptureLocation::new(0),
            })?;
        if block_size < PCAPNG_SHB_MIN_SIZE || block_size % 4 != 0 {
            return Err(CaptureReaderError::Malformed {
                detail: MalformedCapture::Boundary,
                location: CaptureLocation::new(0),
            });
        }
        if block_size > limits.maximum_block_size {
            return Err(CaptureReaderError::ResourceLimit {
                limit: ReaderLimit::MaximumBlockSize,
                location: CaptureLocation::new(0),
            });
        }
        read_up_to(&mut reader, &mut prefix, block_size)?;
        if prefix.len() < block_size {
            return Err(CaptureReaderError::Incomplete {
                location: CaptureLocation::new(0),
            });
        }
        let capacity = limits
            .initial_buffer_size
            .max(block_size)
            .max(PCAPNG_EPB_MIN_SIZE);
        return Ok((prefix, reader, CaptureFormat::PcapNg, byte_order, capacity));
    }
    if looks_like_legacy_pcap(first_four) {
        let byte_order = if matches!(
            first_four,
            Some([0xa1, 0xb2, 0xc3, 0xd4])
                | Some([0xa1, 0xb2, 0x3c, 0x4d])
                | Some([0xa1, 0xb2, 0xcd, 0x34])
        ) {
            ByteOrder::Big
        } else {
            ByteOrder::Little
        };
        if is_modified_magic(first_four) {
            return Err(CaptureReaderError::Unsupported {
                detail: UnsupportedCapture::ModifiedPcap,
                location: CaptureLocation::new(0),
            });
        }
        read_up_to(&mut reader, &mut prefix, PCAP_HEADER_SIZE)?;
        if prefix.len() < PCAP_HEADER_SIZE {
            return Err(CaptureReaderError::Incomplete {
                location: CaptureLocation::new(0),
            });
        }
        let capacity = limits.initial_buffer_size.max(PCAP_HEADER_SIZE);
        return Ok((
            prefix,
            reader,
            CaptureFormat::LegacyPcap,
            byte_order,
            capacity,
        ));
    }
    let capacity = limits.initial_buffer_size.max(PCAPNG_EPB_MIN_SIZE);
    Ok((
        prefix,
        reader,
        CaptureFormat::Unknown,
        ByteOrder::Little,
        capacity,
    ))
}

fn looks_like_legacy_pcap(bytes: Option<&[u8]>) -> bool {
    matches!(
        bytes,
        Some([0xd4, 0xc3, 0xb2, 0xa1])
            | Some([0x4d, 0x3c, 0xb2, 0xa1])
            | Some([0xa1, 0xb2, 0xc3, 0xd4])
            | Some([0xa1, 0xb2, 0x3c, 0x4d])
            | Some([0x34, 0xcd, 0xb2, 0xa1])
            | Some([0xa1, 0xb2, 0xcd, 0x34])
    )
}

fn is_modified_magic(bytes: Option<&[u8]>) -> bool {
    matches!(
        bytes,
        Some([0x34, 0xcd, 0xb2, 0xa1]) | Some([0xa1, 0xb2, 0xcd, 0x34])
    )
}

fn read_up_to<R: Read>(
    reader: &mut R,
    destination: &mut Vec<u8>,
    target: usize,
) -> Result<(), CaptureReaderError> {
    let mut scratch = [0u8; 4096];
    while destination.len() < target {
        let count = (target - destination.len()).min(scratch.len());
        let read = reader
            .read(&mut scratch[..count])
            .map_err(|error| CaptureReaderError::Io {
                kind: error.kind(),
                location: CaptureLocation::new(
                    u64::try_from(destination.len()).unwrap_or(u64::MAX),
                ),
            })?;
        if read == 0 {
            break;
        }
        destination.extend_from_slice(&scratch[..read]);
    }
    Ok(())
}

struct PrefixReader<R> {
    prefix: Vec<u8>,
    position: usize,
    reader: R,
}

impl<R> PrefixReader<R> {
    fn with_reader(prefix: Vec<u8>, reader: R) -> Self {
        Self {
            prefix,
            position: 0,
            reader,
        }
    }
}

impl<R: Read> Read for PrefixReader<R> {
    fn read(&mut self, destination: &mut [u8]) -> io::Result<usize> {
        if self.position < self.prefix.len() {
            let available = self.prefix.len() - self.position;
            let count = available.min(destination.len());
            let end = match self.position.checked_add(count) {
                Some(end) => end,
                None => return Err(io::Error::other("prefix reader offset overflow")),
            };
            if let (Some(source), Some(target)) = (
                self.prefix.get(self.position..end),
                destination.get_mut(..count),
            ) {
                target.copy_from_slice(source);
                self.position = end;
                return Ok(count);
            }
            return Err(io::Error::other("prefix reader boundary invariant"));
        }
        self.reader.read(destination)
    }
}
