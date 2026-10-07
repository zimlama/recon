import { test, expect } from '@playwright/test';

test.describe('Smoke tests', () => {
  test('home page loads and shows branding', async ({ page }) => {
    await page.goto('/');
    await expect(page.getByText('zimlama recon')).toBeVisible();
  });

  test('jobs page renders', async ({ page }) => {
    await page.goto('/jobs');
    await expect(page.getByRole('heading', { name: /Jobs/i })).toBeVisible();
  });

  test('new job page renders form', async ({ page }) => {
    await page.goto('/jobs/new');
    await expect(page.getByText(/New Recon Job/i)).toBeVisible();
  });

  test('modules catalog page shows modules', async ({ page }) => {
    await page.goto('/modules');
    await expect(page.getByText('whois_rdap')).toBeVisible();
  });

  test('disclaimer page shows LATAM-aware legal text', async ({ page }) => {
    await page.goto('/disclaimer');
    await expect(page.getByText(/Pentester Responsibility/i)).toBeVisible();
  });

  test('submit button is disabled with empty target', async ({ page }) => {
    await page.goto('/jobs/new');
    const submit = page.getByTestId('submit-job');
    await expect(submit).toBeDisabled();
  });
});
