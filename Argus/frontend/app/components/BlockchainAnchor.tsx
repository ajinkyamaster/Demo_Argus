"use client";

import { useState } from "react";
import {
  Link,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Loader2,
} from "lucide-react";

interface Props {
  scanId: string;
  reportJson: string;
}

interface AnchorResult {
  pdf_hash: string;
  tx_hash: string;
  block_number: number;
  block_timestamp: number;
  etherscan_url: string;
}

export function BlockchainAnchor({ scanId, reportJson }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [copied, setCopied] = useState(false);
  const [status, setStatus] = useState<
    "idle" | "anchoring" | "anchored" | "error"
  >("idle");
  const [anchor, setAnchor] = useState<AnchorResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function handleAnchor() {
    setStatus("anchoring");
    setError(null);
    try {
      const res = await fetch(`/api/scan/${scanId}/report/anchor`, {
        method: "POST",
      });
      if (!res.ok) {
        const detail = await res.text();
        throw new Error(`Anchor failed: ${res.status} ${detail}`);
      }
      const data: AnchorResult = await res.json();
      setAnchor(data);
      setStatus("anchored");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unknown error");
      setStatus("error");
    }
  }

  function copyHash() {
    if (!anchor?.pdf_hash) return;
    navigator.clipboard.writeText(anchor.pdf_hash).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  const truncatedHash = anchor?.pdf_hash
    ? `${anchor.pdf_hash.slice(0, 8)}...${anchor.pdf_hash.slice(-8)}`
    : "...";

  return (
    <div className="animate-fade-in-up">
      {/* Idle — show "Anchor on Chain" button */}
      {status === "idle" && (
        <button
          type="button"
          onClick={handleAnchor}
          className="inline-flex items-center gap-2 rounded-full border border-zinc-700 bg-zinc-900 px-4 py-2 text-xs font-semibold text-zinc-400 hover:bg-zinc-800 hover:text-zinc-200 transition-all"
        >
          <Link className="h-3.5 w-3.5" />
          Anchor Report on Chain
        </button>
      )}

      {/* Anchoring — spinner */}
      {status === "anchoring" && (
        <button
          type="button"
          disabled
          className="inline-flex items-center gap-2 rounded-full border border-zinc-700 bg-zinc-900 px-4 py-2 text-xs font-semibold text-zinc-500"
        >
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          Submitting to Sepolia... (~15s)
        </button>
      )}

      {/* Error — retry button */}
      {status === "error" && (
        <div className="space-y-2">
          <button
            type="button"
            onClick={handleAnchor}
            className="inline-flex items-center gap-2 rounded-full border border-red-700 bg-red-950/40 px-4 py-2 text-xs font-semibold text-red-400 hover:bg-red-950/60 transition-all"
          >
            <Link className="h-3.5 w-3.5" />
            Retry Anchor
          </button>
          {error && <p className="text-xs text-red-500">{error}</p>}
        </div>
      )}

      {/* Anchored — green pill with expandable details */}
      {status === "anchored" && anchor && (
        <>
          <button
            type="button"
            onClick={() => setExpanded((v) => !v)}
            className="inline-flex items-center gap-2 rounded-full border border-green-700 bg-green-950/40 text-green-400 px-4 py-2 text-xs font-semibold hover:bg-green-950/60 transition-all"
            style={{ boxShadow: "0 0 16px rgba(34, 197, 94, 0.2)" }}
          >
            <Link className="h-3.5 w-3.5" />
            Report anchored
            <span className="terminal text-green-600">{truncatedHash}</span>
            {expanded ? (
              <ChevronUp className="h-3 w-3 ml-1" />
            ) : (
              <ChevronDown className="h-3 w-3 ml-1" />
            )}
          </button>

          {/* Expanded panel */}
          {expanded && (
            <div className="mt-3 rounded-xl border border-zinc-800 bg-zinc-950 p-5 space-y-4 animate-fade-in-up">
              {/* Full SHA-256 */}
              <div>
                <div className="text-xs font-semibold uppercase tracking-wider text-zinc-500 mb-1">
                  PDF SHA-256
                </div>
                <div className="flex items-center gap-2">
                  <code className="flex-1 rounded bg-zinc-900 px-3 py-2 text-xs terminal text-green-400 break-all">
                    {anchor.pdf_hash}
                  </code>
                  <button
                    type="button"
                    onClick={copyHash}
                    className="rounded p-1.5 text-zinc-500 hover:text-zinc-200 hover:bg-zinc-800 transition flex-shrink-0"
                  >
                    {copied ? (
                      <Check className="h-3.5 w-3.5 text-green-400" />
                    ) : (
                      <Copy className="h-3.5 w-3.5" />
                    )}
                  </button>
                </div>
              </div>

              {/* On-chain details */}
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <div className="text-xs text-zinc-600 mb-0.5">Block</div>
                  <div className="text-sm terminal text-zinc-300">
                    #{anchor.block_number}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-zinc-600 mb-0.5">Timestamp</div>
                  <div className="text-sm terminal text-zinc-300">
                    {new Date(anchor.block_timestamp * 1000)
                      .toISOString()
                      .slice(0, 19)
                      .replace("T", " ")}{" "}
                    UTC
                  </div>
                </div>
                <div>
                  <div className="text-xs text-zinc-600 mb-0.5">Tx Hash</div>
                  <div className="text-sm terminal text-zinc-300 break-all">
                    {anchor.tx_hash.slice(0, 14)}...{anchor.tx_hash.slice(-8)}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-zinc-600 mb-0.5">Network</div>
                  <div className="text-sm terminal text-zinc-300">
                    Sepolia Testnet
                  </div>
                </div>
              </div>

              {/* Etherscan link */}
              <a
                href={anchor.etherscan_url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-xs font-semibold text-zinc-300 hover:bg-zinc-800 hover:text-white transition-all"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                Verify on Etherscan
              </a>

              {/* Methodology */}
              <div className="text-xs text-zinc-600 leading-relaxed">
                The PDF report is hashed with SHA-256. The 32-byte digest is
                stored on Sepolia via a{" "}
                <code className="text-zinc-400">storeHash(bytes32)</code> call.
                The block timestamp provides cryptographic proof of when the scan
                was completed. The report content cannot be altered without
                invalidating the on-chain hash.
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
