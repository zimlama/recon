import { describe, it, expect, beforeEach, vi } from 'vitest';

vi.mock('@/lib/api-client', () => ({
  listJobs: vi.fn(),
  getJob: vi.fn(),
  createJob: vi.fn(),
  cancelJob: vi.fn(),
  deleteJob: vi.fn(),
}));

import { useJobsStore } from '@/stores/jobs-store';
import { listJobs, getJob, createJob, cancelJob, deleteJob } from '@/lib/api-client';

const mockedListJobs = vi.mocked(listJobs);
const mockedGetJob = vi.mocked(getJob);
const mockedCreateJob = vi.mocked(createJob);
const mockedCancelJob = vi.mocked(cancelJob);
const mockedDeleteJob = vi.mocked(deleteJob);

describe('jobs-store', () => {
  beforeEach(() => {
    useJobsStore.setState({
      jobs: [],
      currentJob: null,
      loading: false,
      error: null,
    });
    vi.clearAllMocks();
  });

  it('starts empty', () => {
    const state = useJobsStore.getState();
    expect(state.jobs).toEqual([]);
    expect(state.loading).toBe(false);
    expect(state.error).toBeNull();
  });

  it('fetchJobs populates jobs on success', async () => {
    mockedListJobs.mockResolvedValue({
      items: [{ id: 'j-1', target: 'example.com' } as any],
      total: 1,
    });
    await useJobsStore.getState().fetchJobs();
    const state = useJobsStore.getState();
    expect(state.jobs).toHaveLength(1);
    expect(state.loading).toBe(false);
  });

  it('fetchJobs sets error on failure', async () => {
    mockedListJobs.mockRejectedValue(new Error('boom'));
    await useJobsStore.getState().fetchJobs();
    expect(useJobsStore.getState().error).toBe('boom');
    expect(useJobsStore.getState().loading).toBe(false);
  });

  it('fetchJob sets currentJob on success', async () => {
    mockedGetJob.mockResolvedValue({ id: 'j-1', target: 'example.com' } as any);
    await useJobsStore.getState().fetchJob('j-1');
    expect(useJobsStore.getState().currentJob?.id).toBe('j-1');
  });

  it('fetchJob sets error on failure', async () => {
    mockedGetJob.mockRejectedValue(new Error('not found'));
    await useJobsStore.getState().fetchJob('j-1');
    expect(useJobsStore.getState().error).toBe('not found');
  });

  it('createJob adds new job to list on success', async () => {
    mockedCreateJob.mockResolvedValue({ id: 'j-2', target: 'test.com' } as any);
    const job = await useJobsStore.getState().createJob({
      target: 'test.com',
      selected_modules: ['whois_rdap'],
      user_consent: true,
      typed_confirmation: 'test.com',
    });
    expect(job.id).toBe('j-2');
    expect(useJobsStore.getState().jobs[0].id).toBe('j-2');
  });

  it('createJob throws on failure (and rethrows)', async () => {
    mockedCreateJob.mockRejectedValue(new Error('API error'));
    await expect(
      useJobsStore.getState().createJob({
        target: 'test.com',
        selected_modules: ['whois_rdap'],
        user_consent: true,
        typed_confirmation: 'test.com',
      }),
    ).rejects.toThrow('API error');
    expect(useJobsStore.getState().error).toBe('API error');
  });

  it('cancelJob updates job in list', async () => {
    useJobsStore.setState({
      jobs: [{ id: 'j-3', status: 'running' } as any],
      currentJob: { id: 'j-3', status: 'running' } as any,
      loading: false,
      error: null,
    });
    mockedCancelJob.mockResolvedValue({ id: 'j-3', status: 'cancelled' } as any);
    await useJobsStore.getState().cancelJob('j-3');
    expect(useJobsStore.getState().jobs[0].status).toBe('cancelled');
    expect(useJobsStore.getState().currentJob?.status).toBe('cancelled');
  });

  it('cancelJob sets error on failure', async () => {
    useJobsStore.setState({
      jobs: [{ id: 'j-3', status: 'running' } as any],
      currentJob: { id: 'j-3', status: 'running' } as any,
      loading: false,
      error: null,
    });
    mockedCancelJob.mockRejectedValue(new Error('cannot cancel'));
    await useJobsStore.getState().cancelJob('j-3');
    expect(useJobsStore.getState().error).toBe('cannot cancel');
  });

  it('cancelJob does nothing if job not in list', async () => {
    mockedCancelJob.mockResolvedValue({ id: 'unknown', status: 'cancelled' } as any);
    await useJobsStore.getState().cancelJob('unknown');
    // No error, no state change
    expect(useJobsStore.getState().error).toBeNull();
  });

  it('deleteJob removes job from list', async () => {
    useJobsStore.setState({
      jobs: [{ id: 'j-4' } as any, { id: 'j-5' } as any],
      currentJob: { id: 'j-4' } as any,
      loading: false,
      error: null,
    });
    mockedDeleteJob.mockResolvedValue(undefined);
    await useJobsStore.getState().deleteJob('j-4');
    expect(useJobsStore.getState().jobs).toHaveLength(1);
    expect(useJobsStore.getState().jobs[0].id).toBe('j-5');
    // currentJob is cleared
    expect(useJobsStore.getState().currentJob).toBeNull();
  });

  it('deleteJob sets error on failure', async () => {
    useJobsStore.setState({
      jobs: [{ id: 'j-4' } as any],
      currentJob: null,
      loading: false,
      error: null,
    });
    mockedDeleteJob.mockRejectedValue(new Error('cannot delete'));
    await useJobsStore.getState().deleteJob('j-4');
    expect(useJobsStore.getState().error).toBe('cannot delete');
  });

  it('clearError resets error', () => {
    useJobsStore.setState({ jobs: [], currentJob: null, loading: false, error: 'oops' });
    useJobsStore.getState().clearError();
    expect(useJobsStore.getState().error).toBeNull();
  });
});
