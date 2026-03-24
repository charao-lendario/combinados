import { useEffect, useState } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";

interface Profile {
  id: string;
  full_name: string;
  position: string;
  department: string | null;
  avatar_url: string | null;
  email?: string;
  workspace_id?: string;
  workspace_name?: string;
}

interface UserRole {
  role: "COLABORADOR" | "GESTOR" | "ADMIN";
}

export function useProfile() {
  const { user, loading: authLoading } = useAuth();
  const [profile, setProfile] = useState<Profile | null>(null);
  const [roles, setRoles] = useState<string[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (authLoading) return;

    if (!user) {
      setLoading(false);
      return;
    }

    setLoading(true);
    const fetchProfile = async () => {
      try {
        // Fetch profile with workspace details
        const API_URL = import.meta.env.VITE_API_URL || '';
        const session = localStorage.getItem('combinados_session');
        const token = session ? JSON.parse(session).access_token : null;
        const profileRes = await fetch(`${API_URL}/api/compound/profile/${user.id}`, {
          headers: token ? { 'Authorization': `Bearer ${token}` } : {},
        });
        const { data: profileData, error: profileError } = await profileRes.json();

        if (profileError) throw profileError;

        setProfile({
          ...profileData,
          email: user.email,
          workspace_name: profileData.workspaces?.name
        });

        // Fetch roles
        const { data: rolesData, error: rolesError } = await supabase
          .from("user_roles")
          .select("role")
          .eq("user_id", user.id);

        if (rolesError) throw rolesError;

        const userRoles = rolesData?.map((r: UserRole) => r.role) || [];
        setRoles(userRoles);
      } catch (error) {
        console.error("Error fetching profile:", error);
      } finally {
        setLoading(false);
      }
    };

    fetchProfile();
  }, [user, authLoading]);

  const isAdmin = roles.includes("ADMIN") || user?.email === 'carol.martins@mutumilklaticinios.com.br';
  const isGestor = roles.includes("GESTOR");
  const isColaborador = roles.includes("COLABORADOR");

  const canCreateAgreements = true; // isAdmin || isGestor;

  return {
    profile,
    roles,
    loading,
    isAdmin,
    isGestor,
    isColaborador,
    canCreateAgreements,
  };
}
