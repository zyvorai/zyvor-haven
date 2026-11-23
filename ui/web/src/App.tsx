// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0

import { BrowserRouter, Routes, Route } from 'react-router-dom';
import type { ReactNode } from 'react';
import { AuthProvider } from './context/AuthContext';
import { RequireAuth } from './components/RequireAuth';
import { Landing } from './pages/Landing';
import { LoginPage } from './pages/LoginPage';
import { CommandDeck } from './pages/CommandDeck';
import { DeployWizard } from './pages/DeployWizard';
import { RealmsPage } from './pages/RealmsPage';
import { RealmDetailPage } from './pages/RealmDetailPage';
import { ClientsPage } from './pages/ClientsPage';
import { SettingsPage } from './pages/SettingsPage';
import { PlanesPage } from './pages/PlanesPage';
import { AtlasPage } from './pages/AtlasPage';
import { SecurityPosturePage } from './pages/SecurityPosturePage';
import { TimeMachinePage } from './pages/TimeMachinePage';
import { AccessReviewPage } from './pages/AccessReviewPage';
import { CredentialCenterPage } from './pages/CredentialCenterPage';
import { FederationHubPage } from './pages/FederationHubPage';

function Console({ children }: { children: ReactNode }) {
  return <RequireAuth>{children}</RequireAuth>;
}

export function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/deck" element={<Console><CommandDeck /></Console>} />
          <Route path="/deploy" element={<Console><DeployWizard /></Console>} />
          <Route path="/planes" element={<Console><PlanesPage /></Console>} />
          <Route path="/atlas" element={<Console><AtlasPage /></Console>} />
          <Route path="/realms" element={<Console><RealmsPage /></Console>} />
          <Route path="/realms/:realm" element={<Console><RealmDetailPage /></Console>} />
          <Route path="/clients" element={<Console><ClientsPage /></Console>} />
          <Route path="/security" element={<Console><SecurityPosturePage /></Console>} />
          <Route path="/federation" element={<Console><FederationHubPage /></Console>} />
          <Route path="/credentials" element={<Console><CredentialCenterPage /></Console>} />
          <Route path="/access-review" element={<Console><AccessReviewPage /></Console>} />
          <Route path="/time-machine" element={<Console><TimeMachinePage /></Console>} />
          <Route path="/settings" element={<Console><SettingsPage /></Console>} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}
