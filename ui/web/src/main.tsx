// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { GraphicDefs } from './components/graphics/Art';
import { ThemeProvider } from './context/ThemeContext';
import './styles/global.css';
import './styles/console.css';
import './styles/login.css';
import './styles/guard.css';
import './styles/identityops.css';
import './styles/graphics.css';

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <ThemeProvider>
      <GraphicDefs />
      <App />
    </ThemeProvider>
  </StrictMode>,
);
