// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import { useEffect, useState } from 'react';
import { paletteCommands, type PaletteCommand } from '../data/commands';

type Props = {
  open: boolean;
  onClose: () => void;
  onNavigate: (path: string) => void;
  onShell: (hint?: string) => void;
};

export function CommandPalette({ open, onClose, onNavigate, onShell }: Props) {
  const [query, setQuery] = useState('');
  const [selected, setSelected] = useState(0);

  const filtered = paletteCommands.filter((item) => {
    const q = query.toLowerCase();
    if (!q) return true;
    return (
      item.label.toLowerCase().includes(q) ||
      item.keywords?.some((k) => k.includes(q))
    );
  });

  const execute = (item: PaletteCommand) => {
    if (item.action === 'navigate' && item.path) {
      onNavigate(item.path);
      onClose();
      return;
    }
    onShell(item.hint);
    onClose();
  };

  useEffect(() => {
    if (!open) {
      setQuery('');
      setSelected(0);
    }
  }, [open]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
      }
      if (!open) return;
      if (e.key === 'Escape') onClose();
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setSelected((s) => Math.min(s + 1, Math.max(filtered.length - 1, 0)));
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setSelected((s) => Math.max(s - 1, 0));
      }
      if (e.key === 'Enter' && filtered[selected]) {
        e.preventDefault();
        execute(filtered[selected]);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose, filtered, selected]);

  if (!open) return null;

  return (
    <div className="palette-overlay" onClick={onClose} role="presentation">
      <div
        className="palette-modal"
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label="Command palette"
      >
        <input
          className="palette-input"
          placeholder="Type a command…"
          value={query}
          onChange={(e) => {
            setQuery(e.target.value);
            setSelected(0);
          }}
          autoFocus
        />
        <div className="palette-list">
          {filtered.map((item, i) => (
            <div
              key={item.id}
              className={`palette-item ${i === selected ? 'selected' : ''} ${
                item.action === 'shell' ? 'palette-item--shell' : ''
              }`}
              onClick={() => execute(item)}
              onMouseEnter={() => setSelected(i)}
            >
              <span>{item.label}</span>
              {item.action === 'navigate' ? (
                <span className="palette-item-hint">↵</span>
              ) : (
                <span className="palette-item-soon">{item.hint ?? 'Soon'}</span>
              )}
            </div>
          ))}
          {filtered.length === 0 && (
            <div className="palette-empty">No matching commands</div>
          )}
        </div>
      </div>
    </div>
  );
}

export function useCommandPalette() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setOpen((o) => !o);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return { open, setOpen };
}
