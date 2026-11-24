// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import type { ReactNode } from 'react';
import { EmptyState, type ArtName } from './graphics/Art';

interface Column<T> {
  key: string;
  label: string;
  render?: (row: T) => ReactNode;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  keyField: (row: T) => string;
  onRowClick?: (row: T) => void;
  empty?: string;
  emptyArt?: ArtName;
}

export function DataTable<T>({
  columns,
  rows,
  keyField,
  onRowClick,
  empty = 'No records',
  emptyArt = 'apps',
}: DataTableProps<T>) {
  if (rows.length === 0) {
    return (
      <div className="card data-table-empty">
        <EmptyState compact art={emptyArt} title={empty} />
      </div>
    );
  }
  return (
    <div className="card data-table-wrap">
      <table className="data-table">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} scope="col">
                {c.label}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr
              key={keyField(row)}
              onClick={() => onRowClick?.(row)}
              className={onRowClick ? 'is-clickable' : undefined}
            >
              {columns.map((c) => (
                <td key={c.key}>
                  {c.render ? c.render(row) : String((row as Record<string, unknown>)[c.key] ?? '')}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
