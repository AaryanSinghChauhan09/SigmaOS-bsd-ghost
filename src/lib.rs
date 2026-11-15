//! Ghost BSD: privacy-focused BSD with secure memory wiping and PII redaction.

/// A secure memory buffer that guarantees zeroing on wipe.
pub struct SecureMemory {
    data: Vec<u8>,
    capacity: usize,
}

impl SecureMemory {
    /// Allocate a zeroed secure buffer of `size` bytes.
    pub fn allocate(size: usize) -> Self {
        SecureMemory {
            data: vec![0u8; size],
            capacity: size,
        }
    }

    /// Write `bytes` into the buffer (truncated to capacity).
    pub fn write(&mut self, bytes: &[u8]) {
        let len = bytes.len().min(self.capacity);
        self.data[..len].copy_from_slice(&bytes[..len]);
        for b in self.data[len..].iter_mut() {
            *b = 0;
        }
    }

    /// Overwrite every byte with zero (secure wipe).
    pub fn wipe(&mut self) {
        // Use volatile-style writes to prevent compiler elimination.
        for b in self.data.iter_mut() {
            unsafe { std::ptr::write_volatile(b, 0u8) };
        }
    }

    /// Return `true` if all bytes are zero.
    pub fn is_zeroed(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }

    /// Securely copy contents into a new `SecureMemory` buffer.
    pub fn secure_copy(&self) -> Self {
        SecureMemory {
            data: self.data.clone(),
            capacity: self.capacity,
        }
    }

    /// Return a read-only view of the internal data.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
}

/// PII patterns recognized by the PrivacyFilter.
#[derive(Debug, Clone, PartialEq)]
pub enum PiiKind {
    Email,
    Phone,
    CreditCard,
}

/// Redaction result for a single field.
#[derive(Debug, Clone)]
pub struct RedactedField {
    pub original_len: usize,
    pub kind: PiiKind,
    pub redacted: String,
}

/// Filter that detects and redacts Personally Identifiable Information.
pub struct PrivacyFilter;

impl PrivacyFilter {
    /// Redact PII from `input`.
    ///
    /// Recognized patterns:
    /// - Email addresses (contains `@`)
    /// - Phone numbers (digit sequences of 10–15 chars, optionally with `+`, spaces, dashes)
    /// - Credit card numbers (16 consecutive digits)
    pub fn redact_pii(input: &str) -> String {
        // Simple regex-free PII redaction using pattern matching.
        let mut result = input.to_owned();

        // Email redaction: word@word.word -> [REDACTED_EMAIL]
        result = Self::redact_emails(&result);
        // Credit card: 16 consecutive digits -> [REDACTED_CC]
        result = Self::redact_credit_cards(&result);
        // Phone: sequences that look like phone numbers -> [REDACTED_PHONE]
        result = Self::redact_phones(&result);

        result
    }

    fn redact_emails(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '@' {
                // Walk backward in `out` to find the local part.
                let local_start = out
                    .rfind(|ch: char| !ch.is_alphanumeric() && ch != '.' && ch != '_' && ch != '-')
                    .map(|i| i + 1)
                    .unwrap_or(0);
                let _local: String = out.drain(local_start..).collect();
                // Consume domain part.
                while chars
                    .peek()
                    .map(|ch| ch.is_alphanumeric() || *ch == '.' || *ch == '-')
                    .unwrap_or(false)
                {
                    chars.next();
                }
                out.push_str("[REDACTED_EMAIL]");
            } else {
                out.push(c);
            }
        }
        out
    }

    fn redact_credit_cards(input: &str) -> String {
        let chars: Vec<char> = input.chars().collect();
        let mut out = String::with_capacity(input.len());
        let mut i = 0;
        while i < chars.len() {
            if chars[i].is_ascii_digit() {
                let start = i;
                while i < chars.len() && chars[i].is_ascii_digit() {
                    i += 1;
                }
                let run_len = i - start;
                if run_len == 16 {
                    out.push_str("[REDACTED_CC]");
                } else {
                    for c in &chars[start..i] {
                        out.push(*c);
                    }
                }
            } else {
                out.push(chars[i]);
                i += 1;
            }
        }
        out
    }

    fn redact_phones(input: &str) -> String {
        // Phone: starts with optional +, then 10-15 digits (spaces/dashes allowed between groups)
        // We look for patterns like: +1-800-555-0100, 8005550100, etc.
        let mut out = String::with_capacity(input.len());
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            if chars[i] == '+' || chars[i].is_ascii_digit() {
                let start = i;
                if chars[i] == '+' {
                    i += 1;
                }
                let mut digit_count = 0usize;
                let mut j = i;
                while j < chars.len()
                    && (chars[j].is_ascii_digit() || chars[j] == '-' || chars[j] == ' ')
                {
                    if chars[j].is_ascii_digit() {
                        digit_count += 1;
                    }
                    j += 1;
                }
                if (10..=15).contains(&digit_count) {
                    out.push_str("[REDACTED_PHONE]");
                    i = j;
                } else {
                    out.push(chars[start]);
                    i = start + 1;
                }
            } else {
                out.push(chars[i]);
                i += 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_wipe_aaa() {
        // Arrange
        let mut mem = SecureMemory::allocate(64);
        mem.write(b"sensitive password data 1234567890");
        assert!(
            !mem.is_zeroed(),
            "buffer must contain non-zero data before wipe"
        );

        // Act
        mem.wipe();

        // Assert
        assert!(mem.is_zeroed(), "all bytes must be zero after secure wipe");
    }

    #[test]
    fn test_pii_redaction_aaa() {
        // Arrange
        let input = "Contact alice@example.com or call 8005550199 for support.";

        // Act
        let redacted = PrivacyFilter::redact_pii(input);

        // Assert
        assert!(
            !redacted.contains("alice@example.com"),
            "email must be redacted"
        );
        assert!(
            !redacted.contains("8005550199"),
            "phone number must be redacted"
        );
        assert!(
            redacted.contains("[REDACTED_EMAIL]"),
            "email placeholder must appear"
        );
        assert!(
            redacted.contains("[REDACTED_PHONE]"),
            "phone placeholder must appear"
        );
    }

    #[test]
    fn test_secure_copy_aaa() {
        // Arrange
        let mut original = SecureMemory::allocate(8);
        original.write(b"deadbeef");

        // Act
        let copy = original.secure_copy();
        original.wipe();

        // Assert
        assert!(original.is_zeroed(), "original must be zeroed after wipe");
        assert_eq!(
            copy.as_slice(),
            b"deadbeef",
            "copy must retain original data after original is wiped"
        );
    }
}
