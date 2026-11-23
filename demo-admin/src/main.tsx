import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router";
import { AppRoutes } from "./app/AppRoutes";
import { ADMIN_BASE } from "./app/routes";
import { ManagementSessionGate } from "./app/ManagementSession";
import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "./styles/tokens.css";
import "./styles/app.css";

document.title = window.location.pathname.startsWith(ADMIN_BASE) ? "Hallpass" : "Hallpass demo";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <ManagementSessionGate>
      <BrowserRouter>
        <AppRoutes />
      </BrowserRouter>
    </ManagementSessionGate>
  </StrictMode>
);
