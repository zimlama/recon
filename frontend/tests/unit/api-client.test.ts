import { describe, it, expect, vi, beforeEach } from 'vitest';

const mockApiInstance = {
  get: vi.fn(),
  post: vi.fn(),
  delete: vi.fn(),
  interceptors: { response: { use: vi.fn() } },
};

vi.mock('axios', () => ({
  default: {
    create: vi.fn(() => mockApiInstance),
  },
  create: vi.fn(() => mockApiInstance),
}));

describe('api-client', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockApiInstance.get.mockReset();
    mockApiInstance.post.mockReset();
    mockApiInstance.delete.mockReset();
  });

  describe('module catalog', () => {
    it('listModules', async () => {
      mockApiInstance.get.mockResolvedValue({ data: { modules: [], total: 0 } });
      const { listModules } = await import('@/lib/api-client');
      await listModules();
      expect(mockApiInstance.get).toHaveBeenCalledWith('/api/v1/modules');
    });
  });

  describe('jobs CRUD', () => {
    it('listJobs with status filter', async () => {
      mockApiInstance.get.mockResolvedValue({ data: { items: [], total: 0 } });
      const { listJobs } = await import('@/lib/api-client');
      await listJobs(1, 20, 'completed');
      expect(mockApiInstance.get).toHaveBeenCalledWith('/api/v1/jobs', {
        params: { page: 1, page_size: 20, status: 'completed' },
      });
    });

    it('listJobs without status filter', async () => {
      mockApiInstance.get.mockResolvedValue({ data: { items: [], total: 0 } });
      const { listJobs } = await import('@/lib/api-client');
      await listJobs();
      expect(mockApiInstance.get).toHaveBeenCalledWith('/api/v1/jobs', {
        params: { page: 1, page_size: 20 },
      });
    });

    it('getJob', async () => {
      mockApiInstance.get.mockResolvedValue({ data: { id: 'j-1' } });
      const { getJob } = await import('@/lib/api-client');
      const result = await getJob('j-1');
      expect(mockApiInstance.get).toHaveBeenCalledWith('/api/v1/jobs/j-1');
      expect(result.id).toBe('j-1');
    });

    it('createJob', async () => {
      mockApiInstance.post.mockResolvedValue({ data: { id: 'j-1' } });
      const { createJob } = await import('@/lib/api-client');
      await createJob({
        target: 'acme.com',
        selected_modules: ['whois_rdap'],
        user_consent: true,
        typed_confirmation: 'acme.com',
      });
      expect(mockApiInstance.post).toHaveBeenCalledWith('/api/v1/jobs', {
        target: 'acme.com',
        selected_modules: ['whois_rdap'],
        user_consent: true,
        typed_confirmation: 'acme.com',
      });
    });

    it('cancelJob', async () => {
      mockApiInstance.post.mockResolvedValue({ data: { id: 'j-1', status: 'cancelled' } });
      const { cancelJob } = await import('@/lib/api-client');
      await cancelJob('j-1');
      expect(mockApiInstance.post).toHaveBeenCalledWith('/api/v1/jobs/j-1/cancel');
    });

    it('deleteJob', async () => {
      mockApiInstance.delete.mockResolvedValue({ data: null });
      const { deleteJob } = await import('@/lib/api-client');
      await deleteJob('j-1');
      expect(mockApiInstance.delete).toHaveBeenCalledWith('/api/v1/jobs/j-1');
    });
  });

  describe('findings', () => {
    it('getFindings with no filters', async () => {
      mockApiInstance.get.mockResolvedValue({ data: { items: [], total: 0 } });
      const { getFindings } = await import('@/lib/api-client');
      await getFindings('j-1');
      expect(mockApiInstance.get).toHaveBeenCalledWith('/api/v1/jobs/j-1/findings', {
        params: { page: 1, page_size: 50 },
      });
    });

    it('getFindings with all filters', async () => {
      mockApiInstance.get.mockResolvedValue({ data: { items: [], total: 0 } });
      const { getFindings } = await import('@/lib/api-client');
      await getFindings('j-1', { type: 'subdomain', verdict: 'CONFIRMED', page: 2, pageSize: 100 });
      expect(mockApiInstance.get).toHaveBeenCalledWith('/api/v1/jobs/j-1/findings', {
        params: { type: 'subdomain', verdict: 'CONFIRMED', page: 2, page_size: 100 },
      });
    });
  });

  describe('handoff', () => {
    it('getHandoff', async () => {
      mockApiInstance.get.mockResolvedValue({ data: { schema_version: '1.0.0' } });
      const { getHandoff } = await import('@/lib/api-client');
      const result = await getHandoff('j-1');
      expect(mockApiInstance.get).toHaveBeenCalledWith('/api/v1/jobs/j-1/handoff');
      expect(result.schema_version).toBe('1.0.0');
    });
  });

  describe('reports', () => {
    it('generateReport with default options', async () => {
      mockApiInstance.post.mockResolvedValue({
        data: { job_id: 'j-1', md_path: '/x.md', pdf_path: '/x.pdf', generated_at: '2026-10-06' },
      });
      const { generateReport } = await import('@/lib/api-client');
      await generateReport('j-1');
      expect(mockApiInstance.post).toHaveBeenCalledWith(
        '/api/v1/jobs/j-1/report',
        { include_raw_findings: true, include_ai_insights: true, include_annex: true },
      );
    });

    it('generateReport with custom options', async () => {
      mockApiInstance.post.mockResolvedValue({ data: { job_id: 'j-1' } });
      const { generateReport } = await import('@/lib/api-client');
      await generateReport('j-1', {
        include_raw_findings: false,
        include_ai_insights: true,
        include_annex: false,
      });
      expect(mockApiInstance.post).toHaveBeenCalledWith(
        '/api/v1/jobs/j-1/report',
        { include_raw_findings: false, include_ai_insights: true, include_annex: false },
      );
    });
  });

  describe('AI validation', () => {
    it('triggerValidation (all modules)', async () => {
      mockApiInstance.post.mockResolvedValue({ data: [] });
      const { triggerValidation } = await import('@/lib/api-client');
      await triggerValidation('j-1');
      expect(mockApiInstance.post).toHaveBeenCalledWith('/api/v1/jobs/j-1/validate');
    });

    it('triggerValidation (specific module)', async () => {
      mockApiInstance.post.mockResolvedValue({ data: {} });
      const { triggerValidation } = await import('@/lib/api-client');
      await triggerValidation('j-1', 'whois_rdap');
      expect(mockApiInstance.post).toHaveBeenCalledWith(
        '/api/v1/jobs/j-1/modules/whois_rdap/validate',
      );
    });
  });
});
