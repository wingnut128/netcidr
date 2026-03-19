import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";

export function MainLayout() {
  return (
    <div className="min-h-screen bg-bg">
      <Sidebar />
      <main className="ml-48 p-6">
        <Outlet />
      </main>
    </div>
  );
}
