import { useEffect, useState } from "react";
import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { get } from "../../api";

interface Features {
  ipam: boolean;
  swagger: boolean;
}

export function MainLayout() {
  const [ipamEnabled, setIpamEnabled] = useState(false);
  const [swaggerEnabled, setSwaggerEnabled] = useState(false);

  useEffect(() => {
    get<Features>("/features")
      .then((f) => {
        setIpamEnabled(f.ipam);
        setSwaggerEnabled(f.swagger);
      })
      .catch(() => {
        setIpamEnabled(false);
        setSwaggerEnabled(false);
      });
  }, []);

  return (
    <div className="min-h-screen bg-bg">
      <Sidebar ipamEnabled={ipamEnabled} swaggerEnabled={swaggerEnabled} />
      <main className="ml-52 p-8 max-w-screen-2xl">
        <Outlet />
      </main>
    </div>
  );
}
