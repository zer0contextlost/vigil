use crate::pii::{scan, scan_watchlist, PiiMatch};

pub trait Scanner: Send + Sync {
    fn scan(&self, text: &str) -> Vec<PiiMatch>;
}

pub struct RegexScanner;

impl Scanner for RegexScanner {
    fn scan(&self, text: &str) -> Vec<PiiMatch> {
        scan(text)
    }
}

pub struct WatchlistScanner {
    terms: Vec<String>,
}

impl WatchlistScanner {
    pub fn new(terms: Vec<String>) -> Self {
        Self { terms }
    }
}

impl Scanner for WatchlistScanner {
    fn scan(&self, text: &str) -> Vec<PiiMatch> {
        scan_watchlist(text, &self.terms)
    }
}

pub struct ScannerChain {
    scanners: Vec<Box<dyn Scanner>>,
}

impl ScannerChain {
    pub fn new(scanners: Vec<Box<dyn Scanner>>) -> Self {
        Self { scanners }
    }

    pub fn scan_all(&self, text: &str) -> Vec<PiiMatch> {
        self.scanners.iter().flat_map(|s| s.scan(text)).collect()
    }
}
