import { useCallback, useEffect, useState } from "react";

export type Theme = "light" | "dark";
const KEY = "btc-intel.theme";

/** Light by default, like the reference site. The choice is written to the
 *  document element so CSS owns every colour and nothing re-renders. */
export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(
    () => (document.documentElement.dataset.theme as Theme) || "light",
  );

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      localStorage.setItem(KEY, theme);
    } catch {
      /* private window: the choice simply does not persist */
    }
  }, [theme]);

  return [theme, useCallback(() => setTheme((t) => (t === "dark" ? "light" : "dark")), [])];
}
