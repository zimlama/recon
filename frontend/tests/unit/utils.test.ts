import { describe, it, expect } from 'vitest';
import { formatDate, formatDuration, truncate, cn } from '@/lib/utils';

describe('utils', () => {
  describe('formatDate', () => {
    it('returns em-dash for null', () => {
      expect(formatDate(null)).toBe('\u2014');
    });
    it('returns em-dash for undefined', () => {
      expect(formatDate(undefined)).toBe('\u2014');
    });
    it('formats ISO string', () => {
      const result = formatDate('2026-10-06T14:00:00Z');
      expect(result).toContain('2026');
    });
  });

  describe('formatDuration', () => {
    it('returns em-dash for null/undefined', () => {
      expect(formatDuration(null)).toBe('\u2014');
      expect(formatDuration(undefined)).toBe('\u2014');
    });
    it('formats seconds', () => {
      expect(formatDuration(45)).toBe('45s');
    });
    it('formats minutes + seconds', () => {
      expect(formatDuration(125)).toBe('2m 5s');
    });
    it('handles zero', () => {
      expect(formatDuration(0)).toBe('0s');
    });
  });

  describe('truncate', () => {
    it('returns short string as-is', () => {
      expect(truncate('hi', 10)).toBe('hi');
    });
    it('truncates long string with ellipsis', () => {
      expect(truncate('hello world', 5)).toBe('hell\u2026');
    });
  });

  describe('cn (className merger)', () => {
    it('merges class names', () => {
      expect(cn('a', 'b', 'c')).toBe('a b c');
    });
    it('filters falsy values', () => {
      expect(cn('a', false, null, undefined, 'b')).toBe('a b');
    });
    it('handles empty input', () => {
      expect(cn()).toBe('');
    });
  });
});
