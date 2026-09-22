/** What the alert is built on. Each item says what kind of thing it is, so a
 *  reader never has to guess whether a 64-character string is a transaction or
 *  an address, and transactions link to their propagation tree. */
import { Link } from "react-router-dom";
import { evidenceKind, truncateId } from "../lib/format";
import { CopyValue } from "./ui";

export function EvidenceList({ items }: { items: string[] }) {
  if (!items.length) {
    return <p className="soft">No supporting items were recorded for this alert.</p>;
  }
  return (
    <div className="evidence-list">
      {items.map((item, i) => {
        const kind = evidenceKind(item);
        return (
          <div className="evidence-item" key={`${item}-${i}`}>
            <span className="label">{kind}</span>
            {kind === "transaction" ? (
              <Link to={`/tx/${item}`} title={item} viewTransition>
                {truncateId(item, 16, 8)}
              </Link>
            ) : kind === "wallet" ? (
              <Link to={`/entities/${encodeURIComponent(item)}`} title={item} viewTransition>
                {truncateId(item, 16, 8)}
              </Link>
            ) : (
              <span className="value" title={item}>
                {item}
              </span>
            )}
            <CopyValue value={item} />
          </div>
        );
      })}
    </div>
  );
}
