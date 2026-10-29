import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { Sidebar } from '../components/layout/Sidebar';
import type { UserRole } from '../types';

const nav = (role: UserRole) => {
  render(<Sidebar currentTab="overview" onSelectTab={() => undefined} openIncidentsCount={3} userRole={role} userName="T" />);
  return (name: string) => screen.queryByText(name);
};

describe('Sidebar role gating', () => {
  it('gives a Security Administrator the administration areas', () => {
    const has = nav('Security Administrator');
    for (const item of ['Admin Overview', 'Administration', 'Blocklist', 'SOC Operations', 'Incident Management']) expect(has(item), item).toBeInTheDocument();
  });

  it('keeps administration away from a SOC Analyst', () => {
    const has = nav('SOC Analyst');
    expect(has('Administration')).toBeNull();
    expect(has('Admin Overview')).toBeNull();
    for (const item of ['Overview', 'Incident Management', 'SOC Operations']) expect(has(item), item).toBeInTheDocument();
  });

  it('shows an employee only their own area', () => {
    const has = nav('Employee');
    for (const item of ['Administration', 'SOC Operations', 'Incident Management', 'Blocklist', 'Employees']) expect(has(item), item).toBeNull();
    expect(has('My Dashboard')).toBeInTheDocument();
  });
});
