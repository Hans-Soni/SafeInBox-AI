"""Privacy-Preserving Community Threat Intelligence Service.

Provides O(1) indexed consensus lookups and anonymous crowd aggregation for emails
and URLs. Employs canonical skeleton hashing to match mutated attack templates
without storing or sharing any user PII.
"""

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.threat import CommunityThreatSignal, ThreatLshSignature
from app.schemas.community import CommunityIntelResponse
from app.services.canonical_skeleton import (
    compute_canonical_url_hash,
    compute_text_skeleton_hash
)
from app.services.lsh_engine import (
    compute_text_lsh,
    estimate_jaccard_similarity
)


def get_canonical_hash_for_target(target: str, target_type: str, subject: str = "") -> str:
    """Compute the appropriate canonical hash based on target type."""
    normalized_type = target_type.upper()
    if normalized_type in ("EMAIL", "TEXT"):
        return compute_text_skeleton_hash(target, subject)
    return compute_canonical_url_hash(target)


async def get_community_intel(
    db: AsyncSession,
    target: str,
    target_type: str,
    subject: str = ""
) -> CommunityIntelResponse:
    """
    Retrieve aggregated crowd consensus for an email text or URL in O(1) time.
    Strictly Zero-PII: returns count metrics and consensus verdicts only.
    Matches canonical body skeleton with fallback to subject+body skeleton.
    """
    if not target:
        return CommunityIntelResponse()

    target_hashes = []
    # 1. Primary canonical hash (body text alone for emails, canonical URL for links)
    primary_hash = get_canonical_hash_for_target(target, target_type, "")
    if primary_hash:
        target_hashes.append(primary_hash)

    # 2. Combined hash if subject is present
    if subject and target_type.upper() in ("EMAIL", "TEXT"):
        combined_hash = get_canonical_hash_for_target(target, target_type, subject)
        if combined_hash and combined_hash not in target_hashes:
            target_hashes.append(combined_hash)

    stmt = select(CommunityThreatSignal).where(CommunityThreatSignal.target_hash.in_(target_hashes))
    result = await db.execute(stmt)
    signals = result.scalars().all()

    # Aggregate counts across matched canonical signatures
    total_threat = sum(s.threat_count for s in signals)
    total_safe = sum(s.safe_count for s in signals)

    if signals and (total_threat > 0 or total_safe > 0):
        total_votes = total_threat + total_safe
        threat_ratio = (total_threat / total_votes) if total_votes > 0 else 0.0
        flagged = total_threat > 0 and (total_threat >= total_safe or total_threat >= 2)

        if total_threat > total_safe:
            consensus = "THREAT"
        elif total_safe > total_threat:
            consensus = "SAFE"
        else:
            consensus = "SPLIT"

        if total_threat > 0:
            entity_name = "email template" if target_type.upper() in ("EMAIL", "TEXT") else "link"
            user_plural = "user" if total_threat == 1 else "users"
            message = f"{total_threat} SafeInbox AI {user_plural} reported this {entity_name} as a threat."
        else:
            message = None

        return CommunityIntelResponse(
            flagged=flagged,
            threat_count=total_threat,
            safe_count=total_safe,
            consensus=consensus,
            confidence=round(threat_ratio, 2),
            match_type="EXACT",
            similarity=1.0,
            message=message
        )

    # Tier 2: Locality-Sensitive Hashing (LSH) near-duplicate search for emails
    if target_type.upper() in ("EMAIL", "TEXT"):
        lsh_queries = []
        sig_body, buckets_body = compute_text_lsh(target, "")
        if any(buckets_body):
            lsh_queries.append((sig_body, buckets_body))
        if subject:
            sig_comb, buckets_comb = compute_text_lsh(target, subject)
            if any(buckets_comb):
                lsh_queries.append((sig_comb, buckets_comb))

        best_cand = None
        best_sim = 0.0

        for signature, buckets in lsh_queries:
            bucket_conditions = [
                getattr(ThreatLshSignature, f"b{i}") == buckets[i]
                for i in range(16)
            ]
            lsh_stmt = select(ThreatLshSignature).where(or_(*bucket_conditions)).limit(25)
            lsh_res = await db.execute(lsh_stmt)
            candidates = lsh_res.scalars().all()
            for cand in candidates:
                try:
                    cand_sig = [int(x) for x in cand.minhash_sig.split(",")]
                    sim = estimate_jaccard_similarity(signature, cand_sig)
                    if sim >= 0.50 and sim > best_sim:
                        best_sim = sim
                        best_cand = cand
                except Exception:
                    continue

        if best_cand and best_sim >= 0.50:
            sim_pct = int(round(best_sim * 100))
            user_plural = "user" if best_cand.threat_count == 1 else "users"
            fuzzy_msg = (
                f"{best_cand.threat_count} SafeInbox AI {user_plural} reported a near-identical variant of this email ({sim_pct}% similarity)."
                if best_cand.threat_count > 0 else None
            )
            total_v = best_cand.threat_count + best_cand.safe_count
            conf = round(best_cand.threat_count / total_v, 2) if total_v > 0 else 0.0
            return CommunityIntelResponse(
                flagged=best_cand.threat_count > 0 and (best_cand.threat_count >= best_cand.safe_count or best_cand.threat_count >= 2),
                threat_count=best_cand.threat_count,
                safe_count=best_cand.safe_count,
                consensus="THREAT" if best_cand.threat_count > best_cand.safe_count else ("SAFE" if best_cand.safe_count > best_cand.threat_count else "SPLIT"),
                confidence=conf,
                match_type="FUZZY_LSH",
                similarity=best_sim,
                message=fuzzy_msg
            )

    return CommunityIntelResponse(
        flagged=False,
        threat_count=0,
        safe_count=0,
        consensus="NONE",
        confidence=0.0,
        match_type="NONE",
        similarity=0.0,
        message=None
    )


async def record_community_feedback(
    db: AsyncSession,
    target: str,
    target_type: str,
    is_safe: bool,
    subject: str = ""
) -> tuple[str, CommunityIntelResponse]:
    """
    Record community vote into the aggregated consensus table in O(1) time.
    Returns (canonical_hash, updated_intel).
    """
    target_hash = get_canonical_hash_for_target(target, target_type, subject)

    stmt = select(CommunityThreatSignal).where(CommunityThreatSignal.target_hash == target_hash)
    result = await db.execute(stmt)
    signal = result.scalar_one_or_none()

    normalized_type = "EMAIL" if target_type.upper() in ("EMAIL", "TEXT") else "URL"

    if signal:
        if is_safe:
            signal.safe_count += 1
        else:
            signal.threat_count += 1
    else:
        signal = CommunityThreatSignal(
            target_hash=target_hash,
            target_type=normalized_type,
            threat_count=0 if is_safe else 1,
            safe_count=1 if is_safe else 0
        )
        db.add(signal)

    # Tier 2: Maintain LSH MinHash signature for fuzzy near-duplicate detection
    if normalized_type == "EMAIL":
        signature, buckets = compute_text_lsh(target, subject)
        if any(buckets):
            sig_str = ",".join(str(x) for x in signature)
            bucket_conditions = [
                getattr(ThreatLshSignature, f"b{i}") == buckets[i]
                for i in range(16)
            ]
            lsh_stmt = select(ThreatLshSignature).where(
                or_(
                    ThreatLshSignature.target_hash == target_hash,
                    and_(*bucket_conditions[:4])
                )
            )
            lsh_res = await db.execute(lsh_stmt)
            existing_lsh = lsh_res.scalars().first()
            if existing_lsh:
                if is_safe:
                    existing_lsh.safe_count += 1
                else:
                    existing_lsh.threat_count += 1
            else:
                bucket_kwargs = {f"b{i}": buckets[i] for i in range(16)}
                new_lsh = ThreatLshSignature(
                    target_hash=target_hash,
                    target_type="EMAIL",
                    minhash_sig=sig_str,
                    threat_count=0 if is_safe else 1,
                    safe_count=1 if is_safe else 0,
                    **bucket_kwargs
                )
                db.add(new_lsh)

    await db.commit()
    await db.refresh(signal)

    total_votes = signal.threat_count + signal.safe_count
    threat_ratio = (signal.threat_count / total_votes) if total_votes > 0 else 0.0
    flagged = signal.threat_count > 0 and (signal.threat_count >= signal.safe_count or signal.threat_count >= 2)

    entity_name = "email template" if normalized_type == "EMAIL" else "link"
    user_plural = "user" if signal.threat_count == 1 else "users"
    message = (
        f"{signal.threat_count} SafeInbox AI {user_plural} reported this {entity_name} as a threat."
        if signal.threat_count > 0 else None
    )

    intel = CommunityIntelResponse(
        flagged=flagged,
        threat_count=signal.threat_count,
        safe_count=signal.safe_count,
        consensus="THREAT" if signal.threat_count > signal.safe_count else ("SAFE" if signal.safe_count > signal.threat_count else "SPLIT"),
        confidence=round(threat_ratio, 2),
        message=message
    )

    return target_hash, intel
