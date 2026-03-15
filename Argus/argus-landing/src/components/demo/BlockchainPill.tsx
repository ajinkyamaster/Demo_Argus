import type { BlockchainAnchor } from '../../types';

export default function BlockchainPill({ data }: { data: BlockchainAnchor }) {
  return <div>BlockchainPill placeholder — block #{data.block_number}</div>;
}
