import { Navigate, Route, Routes, useLocation, useParams } from "react-router";
import { AdminApp } from "./AdminApp";
import { ADMIN_BASE, legacyHashPath, resolveAdminPath } from "./routes";

function AdminRoute() {
  const rest = useParams()["*"] ?? "";
  const { hash } = useLocation();
  const legacy = rest ? undefined : legacyHashPath(hash);
  if (legacy && legacy !== ADMIN_BASE) return <Navigate to={legacy} replace />;
  const route = resolveAdminPath(rest);
  if (route.kind === "redirect") return <Navigate to={route.to} replace />;
  return <AdminApp route={route} />;
}

export function AppRoutes() {
  return (
    <Routes>
      {/* One splat route, so moving between admin screens keeps the admin mounted. */}
      <Route path={`${ADMIN_BASE}/*`} element={<AdminRoute />} />
      {/* The old `/` walkthrough is retired; every other path, including `/#demo`, goes to Home. */}
      <Route path="*" element={<Navigate to={ADMIN_BASE} replace />} />
    </Routes>
  );
}
