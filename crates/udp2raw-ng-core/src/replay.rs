use crate::ReplayError;

/// Sliding replay filter accepting unseen out-of-order packet numbers.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    width: usize,
    highest: Option<u64>,
    words: Vec<u64>,
}

impl ReplayWindow {
    pub fn new(width: usize) -> Self {
        assert!(width > 0, "replay window width must be non-zero");
        Self {
            width,
            highest: None,
            words: vec![0; width.div_ceil(64)],
        }
    }

    pub const fn width(&self) -> usize {
        self.width
    }

    pub const fn highest(&self) -> Option<u64> {
        self.highest
    }

    /// Checks and records a packet number atomically from the caller's point of
    /// view. Authentication must succeed before this method is called.
    pub fn accept(&mut self, packet_number: u64) -> Result<(), ReplayError> {
        let Some(highest) = self.highest else {
            self.highest = Some(packet_number);
            self.set(0);
            return Ok(());
        };

        if packet_number > highest {
            let shift = usize::try_from(packet_number - highest).unwrap_or(usize::MAX);
            self.shift_left(shift);
            self.highest = Some(packet_number);
            self.set(0);
            return Ok(());
        }

        let distance = usize::try_from(highest - packet_number).unwrap_or(usize::MAX);
        if distance >= self.width {
            return Err(ReplayError::TooOld);
        }
        if self.get(distance) {
            return Err(ReplayError::Duplicate);
        }
        self.set(distance);
        Ok(())
    }

    fn get(&self, index: usize) -> bool {
        (self.words[index / 64] & (1_u64 << (index % 64))) != 0
    }

    fn set(&mut self, index: usize) {
        self.words[index / 64] |= 1_u64 << (index % 64);
    }

    fn shift_left(&mut self, amount: usize) {
        if amount >= self.width {
            self.words.fill(0);
            return;
        }
        for index in (amount..self.width).rev() {
            let previous = index - amount;
            let value = self.get(previous);
            if value {
                self.set(index);
            } else {
                self.words[index / 64] &= !(1_u64 << (index % 64));
            }
        }
        for index in 0..amount {
            self.words[index / 64] &= !(1_u64 << (index % 64));
        }
        self.clear_unused_tail();
    }

    fn clear_unused_tail(&mut self) {
        let used_bits = self.width % 64;
        if used_bits != 0 {
            let mask = (1_u64 << used_bits) - 1;
            if let Some(last) = self.words.last_mut() {
                *last &= mask;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ReplayWindow;
    use crate::ReplayError;

    #[test]
    fn accepts_reordering_and_rejects_duplicates() {
        let mut window = ReplayWindow::new(128);
        assert_eq!(window.accept(10), Ok(()));
        assert_eq!(window.accept(12), Ok(()));
        assert_eq!(window.accept(11), Ok(()));
        assert_eq!(window.accept(11), Err(ReplayError::Duplicate));
    }

    #[test]
    fn rejects_packets_outside_window() {
        let mut window = ReplayWindow::new(64);
        window.accept(1).expect("first packet");
        window.accept(100).expect("advance window");
        assert_eq!(window.accept(1), Err(ReplayError::TooOld));
    }
}
