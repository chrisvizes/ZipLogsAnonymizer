//! High-performance anonymization core for ZipLogsAnonymizer
//!
//! This module provides a Rust-based pattern matching engine that is
//! significantly faster than Python's `re` module, using:
//! - Aho-Corasick for O(n) multi-keyword search
//! - Rust's regex crate (same as ripgrep)
//! - Rayon for parallel processing

use pyo3::prelude::*;
use pyo3::types::PyDict;
use std::collections::HashMap;

mod anonymizer;
mod patterns;

use anonymizer::RustAnonymizer;

/// Fast pattern-based anonymization engine exposed to Python
#[pyclass]
pub struct AnonymizerCore {
    inner: RustAnonymizer,
}

#[pymethods]
impl AnonymizerCore {
    #[new]
    fn new() -> PyResult<Self> {
        Ok(Self {
            inner: RustAnonymizer::new(),
        })
    }

    /// Process content and return (anonymized_content, counts_dict)
    fn process_content(&mut self, py: Python<'_>, content: &str) -> PyResult<(String, PyObject)> {
        let (result, counts) = self.inner.process(content);

        let dict = PyDict::new(py);
        for (k, v) in counts {
            dict.set_item(k, v)?;
        }
        Ok((result, dict.into()))
    }

    /// Check if content may contain sensitive data (fast pre-filter)
    fn content_may_have_matches(&self, content: &str) -> bool {
        self.inner.has_keywords(content)
    }

    /// Reset counters for a new file
    fn reset(&mut self) {
        self.inner.reset();
    }

    /// Get the unique replacement mapping for a category
    fn get_unique_counters(&self, py: Python<'_>) -> PyResult<PyObject> {
        let dict = PyDict::new(py);
        for (category, mappings) in self.inner.get_unique_counters() {
            let inner_dict = PyDict::new(py);
            for (original, idx) in mappings {
                inner_dict.set_item(original, idx)?;
            }
            dict.set_item(category, inner_dict)?;
        }
        Ok(dict.into())
    }
}

/// Check if Rust core is available (always true when this module loads)
#[pyfunction]
fn is_rust_core_available() -> bool {
    true
}

/// Get version info
#[pyfunction]
fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Get info about the Rust core
#[pyfunction]
fn get_info() -> HashMap<&'static str, &'static str> {
    let mut info = HashMap::new();
    info.insert("version", env!("CARGO_PKG_VERSION"));
    info.insert("regex_version", "1.10");
    info.insert("aho_corasick_version", "1.1");
    info
}

/// Python module definition
#[pymodule]
fn anonymizer_core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<AnonymizerCore>()?;
    m.add_function(wrap_pyfunction!(is_rust_core_available, m)?)?;
    m.add_function(wrap_pyfunction!(get_version, m)?)?;
    m.add_function(wrap_pyfunction!(get_info, m)?)?;
    Ok(())
}
