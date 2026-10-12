export function matchesSelection(query: string, ...values: (string | number | null | undefined)[]) {
  const needle = query.trim().toLocaleLowerCase();
  return !needle || values.some(value => String(value ?? "").toLocaleLowerCase().includes(needle));
}

export function toggleVisibleSelection<T>(selected: T[], visible: T[], checked: boolean): T[] {
  const visibleSet = new Set(visible);
  return checked ? [...new Set([...selected, ...visible])] : selected.filter(id => !visibleSet.has(id));
}
