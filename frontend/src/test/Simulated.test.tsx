import { render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { SimulatedBadge, SimulatedBanner } from '../components/common/Simulated';

describe('simulated-data labelling', () => {
  it('marks fabricated records', () => {
    render(<SimulatedBadge />);
    expect(screen.getByText(/simulated/i)).toBeInTheDocument();
  });

  it('says plainly when everything shown is simulated', () => {
    render(<SimulatedBanner simulated={10} total={10} />);
    expect(screen.getByText('All data shown is simulated.')).toBeInTheDocument();
  });

  it('gives the count when only some data is simulated', () => {
    render(<SimulatedBanner simulated={4} total={10} />);
    expect(screen.getByText(/4 of 10 events are simulated/)).toBeInTheDocument();
  });

  it('says nothing when no data is simulated', () => {
    const { container } = render(<SimulatedBanner simulated={0} total={10} />);
    expect(container).toBeEmptyDOMElement();
  });
});
