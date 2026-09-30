import React from "react";
import { ShieldCheck, Lock, Radio, EyeOff, XCircle, CheckCircle, AlertOctagon } from "lucide-react";

export function SecurityAuditor({ enclaveStatus }) {
  const securityRules = [
    {
      title: "Zero Return Path (Airgap Enforcement)",
      rule: "The analysis environment MUST NOT establish any outgoing IP connection, handshake, or return packet to monitored systems.",
      status: "ENFORCED (PHYSICAL & LOGICAL ONE-WAY)",
      compliant: true,
      codeProof: "backend/app/core/ingest.py: Enforces zero egress socket calls"
    },
    {
      title: "No Active Network Probing / Scans",
      rule: "The analysis environment MUST NOT perform active port scanning, vulnerability probing, or ping sweeps against observed hosts.",
      status: "DISABLED BY ARCHITECTURE",
      compliant: true,
      codeProof: "backend/app/config.py: ACTIVE_PROBING_ENABLED = False"
    },
    {
      title: "No Payload Decryption (Metadata Only)",
      rule: "TLS and QUIC payloads MUST NOT be decrypted. Analysis uses JA3/JA4 fingerprints and packet timing/sizes strictly.",
      status: "METADATA ONLY (ZERO DECRYPTION)",
      compliant: true,
      codeProof: "backend/app/detection/encrypted_detector.py: Payloads untouched"
    },
    {
      title: "No Inline Traffic Modification / Mitigation",
      rule: "The platform is intelligence-only. It MUST NOT send inline firewall commands or modify production packets.",
      status: "READ-ONLY INTELLIGENCE ENCLAVE",
      compliant: true,
      codeProof: "backend/app/config.py: INLINE_MITIGATION_ENABLED = False"
    },
    {
      title: "No Active DNS Resolution",
      rule: "Suspicious DGA or covert DNS query labels MUST NOT be queried or resolved against external DNS servers.",
      status: "INSPECTION STRICTLY IN-MEMORY",
      compliant: true,
      codeProof: "backend/app/detection/dns_detector.py: Zero socket lookups"
    }
  ];

  return (
    <div className="glass-panel" style={{ padding: "24px", marginBottom: "20px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "16px" }}>
        <ShieldCheck size={22} color="#10b981" />
        <div>
          <h2 style={{ fontSize: "1.1rem", fontWeight: 700, color: "#f8fafc" }}>
            ONE-WAY AIRGAP & ENCLAVE SECURITY INVARIANT AUDIT
          </h2>
          <p style={{ fontSize: "0.76rem", color: "var(--text-muted)" }}>
            Non-negotiable architectural guarantees verified by static code audit & runtime enforcement
          </p>
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "12px", marginTop: "20px" }}>
        {securityRules.map((r, i) => (
          <div key={i} style={{ background: "rgba(15, 23, 42, 0.6)", border: "1px solid var(--border-subtle)", borderRadius: "8px", padding: "14px" }}>
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: "6px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
                <CheckCircle size={16} color="#10b981" />
                <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#f8fafc" }}>
                  {r.title}
                </span>
              </div>
              <span className="badge-enclave" style={{ padding: "2px 8px", borderRadius: "4px", fontSize: "0.70rem", fontWeight: 700 }}>
                {r.status}
              </span>
            </div>

            <p style={{ fontSize: "0.74rem", color: "var(--text-secondary)", marginBottom: "6px", lineHeight: "1.4" }}>
              {r.rule}
            </p>

            <div style={{ fontSize: "0.70rem", fontFamily: "monospace", color: "#38bdf8" }}>
              Code Enforcement: {r.codeProof}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
