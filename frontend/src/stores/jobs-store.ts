import { create } from 'zustand';
import type { Job, JobCreate, JobStatus } from '@/lib/api-client';
import * as api from '@/lib/api-client';

interface JobsState {
  jobs: Job[];
  currentJob: Job | null;
  loading: boolean;
  error: string | null;

  fetchJobs: (status?: JobStatus) => Promise<void>;
  fetchJob: (id: string) => Promise<void>;
  createJob: (payload: JobCreate) => Promise<Job>;
  cancelJob: (id: string) => Promise<void>;
  deleteJob: (id: string) => Promise<void>;
  clearError: () => void;
}

export const useJobsStore = create<JobsState>((set, get) => ({
  jobs: [],
  currentJob: null,
  loading: false,
  error: null,

  fetchJobs: async (status) => {
    set({ loading: true, error: null });
    try {
      const data = await api.listJobs(1, 100, status);
      set({ jobs: data.items, loading: false });
    } catch (e) {
      set({ error: (e as Error).message, loading: false });
    }
  },

  fetchJob: async (id) => {
    set({ loading: true, error: null });
    try {
      const job = await api.getJob(id);
      set({ currentJob: job, loading: false });
    } catch (e) {
      set({ error: (e as Error).message, loading: false });
    }
  },

  createJob: async (payload) => {
    set({ loading: true, error: null });
    try {
      const job = await api.createJob(payload);
      set((s) => ({ jobs: [job, ...s.jobs], loading: false }));
      return job;
    } catch (e) {
      const msg = (e as Error).message;
      set({ error: msg, loading: false });
      throw new Error(msg);
    }
  },

  cancelJob: async (id) => {
    set({ error: null });
    try {
      const job = await api.cancelJob(id);
      set((s) => ({
        jobs: s.jobs.map((j) => (j.id === id ? job : j)),
        currentJob: s.currentJob?.id === id ? job : s.currentJob,
      }));
    } catch (e) {
      set({ error: (e as Error).message });
    }
  },

  deleteJob: async (id) => {
    set({ error: null });
    try {
      await api.deleteJob(id);
      set((s) => ({
        jobs: s.jobs.filter((j) => j.id !== id),
        currentJob: s.currentJob?.id === id ? null : s.currentJob,
      }));
    } catch (e) {
      set({ error: (e as Error).message });
    }
  },

  clearError: () => set({ error: null }),
}));
