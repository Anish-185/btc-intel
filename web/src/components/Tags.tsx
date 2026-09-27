/** Attribution tags (intel/, docs/TAGSTORE.md): what the imported bundles say
 *  an address or cluster is, each with its source and collection date. A tag
 *  names a service or a category, never a person. Simulated tags say so on
 *  every row; conflicting tags are all shown, never resolved. */
import { api } from "../api/client";
import type { EntityTags, ShownTag, TagsResponse } from "../api/types";
import { useApi } from "../lib/useApi";
import { formatId } from "../lib/formatId";
import { Chip, ErrorNote, Label, Notice } from "./ui";

type Kind = "entity" | "transaction" | "actor" | "peer";

function TagRow({ tag }: { tag: ShownTag }) {
  return (
    <li>
      <strong>{tag.label}</strong> <Chip>{tag.category}</Chip>{" "}
      {tag.simulated && <Chip tone="caution">simulated, not intelligence</Chip>}
      <span className="soft" style={{ fontSize: "var(--fs-small)" }}>
        {" "}
        · {tag.source}, collected {tag.collected} · {tag.basis} · confidence{" "}
        <span className="num">{tag.effective_confidence.toFixed(2)}</span> · {tag.reference}
      </span>
    </li>
  );
}

function Group({ title, tags, conflict }: { title: string; tags: ShownTag[]; conflict: boolean }) {
  return (
    <div style={{ marginTop: "var(--sp-3)" }}>
      <Label>{title}</Label>
      {conflict && (
        <Notice title="conflicting tags">
          The sources disagree about this subject. Every tag is shown; none is preferred.
        </Notice>
      )}
      <ul>
        {tags.map((t) => (
          <TagRow key={`${t.bundle}-${t.subject}-${t.label}`} tag={t} />
        ))}
      </ul>
    </div>
  );
}

function entityGroups(e: EntityTags, many: boolean) {
  const out = [];
  if (e.tags.length)
    out.push(
      <Group
        key={`${e.entity_id}-c`}
        title={many ? `cluster ${formatId(e.entity_id)}` : "this cluster"}
        tags={e.tags}
        conflict={e.conflict}
      />,
    );
  if (e.member_tags.length)
    out.push(
      <Group
        key={`${e.entity_id}-m`}
        title={`addresses in ${formatId(e.entity_id)}, not extended to the cluster`}
        tags={e.member_tags}
        conflict={e.conflict && !e.tags.length}
      />,
    );
  return out;
}

export function TagsBody({ data }: { data: TagsResponse }) {
  const many = data.entities.length > 1;
  const groups = [
    ...data.entities.flatMap((e) => entityGroups(e, many)),
    ...data.addresses.map((a) => (
      <Group key={a.address} title={`address ${formatId(a.address)}`} tags={a.tags} conflict={a.conflict} />
    )),
  ];
  const loaded = data.bundles.filter((b) => b.ok).length;
  return (
    <>
      <p className="soft" style={{ fontSize: "var(--fs-small)" }}>
        {data.statement} {loaded} bundle{loaded === 1 ? "" : "s"} loaded, {data.tags} tags.
        {many && " Each cluster's tags stay with that cluster."}
      </p>
      {groups.length ? groups : <p className="soft">No tags for this {data.kind}.</p>}
    </>
  );
}

export function TagsSection({ kind, subject }: { kind: Kind; subject: string }) {
  const { data, error } = useApi((signal) => api.tags(kind, subject, signal), [kind, subject]);
  return (
    <section className="section" id="tags" aria-label="Tags">
      <div className="section-head">
        <h2>Tags</h2>
        {data?.simulated && <Chip tone="caution">simulated bundle loaded</Chip>}
      </div>
      {error ? <ErrorNote error={error} /> : data ? <TagsBody data={data} /> : null}
    </section>
  );
}
