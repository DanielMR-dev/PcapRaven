//! Deterministic, bounded registry for active detectors.

use crate::detector::Detector;
use crate::error::DetectorRegistryError;
use core::fmt;
use pcapraven_domain::DetectorId;

/// Deterministic, bounded registry holding active compiled detector implementations.
///
/// Ensures strict deduplication of [`DetectorId`]s and enforces that execution order
/// is strictly governed by canonical `DetectorId` ordering regardless of registration sequence.
pub struct DetectorRegistry {
    detectors: Vec<Box<dyn Detector>>,
    max_capacity: usize,
}

impl fmt::Debug for DetectorRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DetectorRegistry")
            .field("detectors_len", &self.detectors.len())
            .field("max_capacity", &self.max_capacity)
            .finish()
    }
}

impl DetectorRegistry {
    /// Default maximum number of registered detectors (64).
    pub const DEFAULT_MAX_REGISTERED_DETECTORS: usize = 64;
    /// Hard maximum cap on registered detectors (256).
    pub const HARD_MAX_REGISTERED_DETECTORS: usize = 256;

    /// Creates a new detector registry with the specified capacity limit.
    pub fn new(max_capacity: usize) -> Result<Self, DetectorRegistryError> {
        if max_capacity == 0 {
            return Err(DetectorRegistryError::ZeroRegistryCapacity);
        }
        if max_capacity > Self::HARD_MAX_REGISTERED_DETECTORS {
            return Err(DetectorRegistryError::RegistryCapacityAboveHardMaximum {
                attempted: max_capacity,
                max: Self::HARD_MAX_REGISTERED_DETECTORS,
            });
        }
        Ok(Self {
            detectors: Vec::with_capacity(max_capacity.min(32)),
            max_capacity,
        })
    }

    /// Registers a detector instance.
    ///
    /// Returns an error if the registry is full or if a detector with the same [`DetectorId`]
    /// is already registered. Execution order is always sorted by `DetectorId`.
    pub fn register(&mut self, detector: Box<dyn Detector>) -> Result<(), DetectorRegistryError> {
        if self.detectors.len() >= self.max_capacity {
            return Err(DetectorRegistryError::RegistryCapacityExceeded {
                count: self.detectors.len() + 1,
                max: self.max_capacity,
            });
        }

        let new_id = detector.metadata().id();
        if self.detectors.iter().any(|d| d.metadata().id() == new_id) {
            return Err(DetectorRegistryError::DuplicateDetectorId(new_id.clone()));
        }

        self.detectors.push(detector);
        // Maintain deterministic canonical order by DetectorId
        self.detectors
            .sort_by(|a, b| a.metadata().id().cmp(b.metadata().id()));
        Ok(())
    }

    /// Returns the number of registered detectors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    /// Returns `true` if the registry contains zero detectors.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }

    /// Returns the maximum capacity of the registry.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.max_capacity
    }

    /// Looks up a registered detector by its identifier.
    #[must_use]
    pub fn get(&self, id: &DetectorId) -> Option<&dyn Detector> {
        self.detectors
            .iter()
            .find(|d| d.metadata().id() == id)
            .map(|d| d.as_ref())
    }

    /// Returns an iterator over references to all registered detectors in canonical ID order.
    pub fn iter(&self) -> impl Iterator<Item = &dyn Detector> {
        self.detectors.iter().map(|d| d.as_ref())
    }
}

impl Default for DetectorRegistry {
    fn default() -> Self {
        Self {
            detectors: Vec::new(),
            max_capacity: Self::DEFAULT_MAX_REGISTERED_DETECTORS,
        }
    }
}
