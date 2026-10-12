import React from "react";

// A minimal hook host for the installed React 18 dispatcher. It runs the actual
// source hooks, effects and state setters without requiring a browser renderer.
export function mountHook(hook, ...initialArgs) {
  const slots = [];
  let args = initialArgs, index = 0, dirty = true, mounted = true, value;
  let effects = [], updatesAfterUnmount = 0;
  const same = (a, b) => a && b && a.length === b.length && a.every((v, i) => Object.is(v, b[i]));
  const dispatcher = {
    useState(initial) {
      const position = index++;
      if (!slots[position]) {
        const slot = { value: typeof initial === "function" ? initial() : initial };
        slot.set = next => {
          if (!mounted) { updatesAfterUnmount++; return; }
          const result = typeof next === "function" ? next(slot.value) : next;
          if (!Object.is(result, slot.value)) { slot.value = result; dirty = true; }
        };
        slots[position] = slot;
      }
      return [slots[position].value, slots[position].set];
    },
    useRef(initial) {
      const position = index++;
      return slots[position] ||= { current: initial };
    },
    useCallback(callback, deps) {
      const position = index++;
      if (!same(slots[position]?.deps, deps)) slots[position] = { value: callback, deps };
      return slots[position].value;
    },
    useEffect(create, deps) {
      const position = index++;
      if (!same(slots[position]?.deps, deps)) {
        const previous = slots[position];
        const slot = { deps, cleanup: undefined };
        slots[position] = slot;
        effects.push({ previous, slot, create });
      }
    },
  };
  const host = {
    get current() { return value; },
    get updatesAfterUnmount() { return updatesAfterUnmount; },
    render(...nextArgs) {
      if (nextArgs.length) args = nextArgs;
      do {
        dirty = false;
        index = 0;
        effects = [];
        const current = React.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED.ReactCurrentDispatcher;
        const previous = current.current;
        current.current = dispatcher;
        try { value = hook(...args); } finally { current.current = previous; }
        for (const effect of effects) effect.previous?.cleanup?.();
        for (const effect of effects) effect.slot.cleanup = effect.create();
      } while (dirty);
      return value;
    },
    unmount() {
      mounted = false;
      for (const slot of slots) slot?.cleanup?.();
    },
  };
  host.render();
  return host;
}

export const settle = () => new Promise(resolve => setImmediate(resolve));
