import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useProfile } from "@/hooks/useProfile";
import { useRealtimeNotifications } from "@/hooks/useRealtimeNotifications";
import { supabase } from "@/integrations/supabase/client";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Plus, Calendar, Users, CheckCircle2, Clock, AlertCircle } from "lucide-react";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { Badge } from "@/components/ui/badge";

export default function AgreementsIndex() {
  const { user, loading: authLoading } = useAuth();
  const { canCreateAgreements, loading: profileLoading } = useProfile();
  const navigate = useNavigate();

  // Hook para notificações em tempo real
  useRealtimeNotifications(user?.id);

  useEffect(() => {
    if (!authLoading && !user) {
      navigate("/auth");
    }
  }, [user, authLoading, navigate]);

  const { data: agreements, isLoading: agreementsLoading } = useQuery({
    queryKey: ["agreements", user?.id],
    queryFn: async () => {
      if (!user) return [];

      // 1. Buscar IDs dos combinados onde sou participante
      const { data: participations } = await supabase
        .from('agreement_participants')
        .select('agreement_id')
        .eq('user_id', user.id);

      const participationIds = participations?.map(p => p.agreement_id) || [];

      // 2. Buscar combinados com contagem de participantes
      const API_URL = import.meta.env.VITE_API_URL || '';
      const session = localStorage.getItem('combinados_session');
      const token = session ? JSON.parse(session).access_token : null;
      const res = await fetch(`${API_URL}/api/compound/agreements/list`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({
          userId: user.id,
          participationIds,
          orderBy: 'created_at',
          orderAsc: false,
        }),
      });
      const { data, error } = await res.json();

      if (error) {
        console.error("Erro ao buscar combinados:", error);
        throw error;
      }

      return data;
    },
    enabled: !!user,
  });

  const loading = authLoading || profileLoading || agreementsLoading;

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-background via-secondary/5 to-primary/5">
        <Header />
        <main className="container py-8">
          <Skeleton className="h-12 w-64 mb-8" />
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
            {[1, 2, 3, 4, 5, 6].map((i) => (
              <Skeleton key={i} className="h-48" />
            ))}
          </div>
        </main>
      </div>
    );
  }

  if (!user) return null;

  const getStatusColor = (status: string) => {
    switch (status) {
      case "COMPLETED":
        return "bg-green-500/10 text-green-500 hover:bg-green-500/20";
      case "IN_PROGRESS":
        return "bg-blue-500/10 text-blue-500 hover:bg-blue-500/20";
      case "PENDING":
        return "bg-yellow-500/10 text-yellow-500 hover:bg-yellow-500/20";
      case "OVERDUE":
        return "bg-red-500/10 text-red-500 hover:bg-red-500/20";
      default:
        return "bg-secondary text-secondary-foreground";
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case "COMPLETED":
        return "Concluído";
      case "IN_PROGRESS":
        return "Em Andamento";
      case "PENDING":
        return "Pendente";
      case "OVERDUE":
        return "Atrasado";
      case "DRAFT":
        return "Rascunho";
      case "ACCEPTED":
        return "Aceito";
      case "REJECTED":
        return "Rejeitado";
      case "CANCELLED":
        return "Cancelado";
      default:
        return status;
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/5 to-primary/5">
      <Header />
      <main className="container py-8">
        <div className="space-y-8">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-3xl font-bold tracking-tight">
                Meus Combinados
              </h2>
              <p className="text-muted-foreground">
                Gerencie todos os seus combinados corporativos
              </p>
            </div>
            {canCreateAgreements && (
              <Button onClick={() => { console.log("[AgreementsIndex] Novo Combinado click"); navigate("/agreements/new"); }}>
                <Plus className="mr-2 h-4 w-4" />
                Novo Combinado
              </Button>
            )}
          </div>

          {/* Agreements Grid */}
          {agreements && agreements.length > 0 ? (
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
              {agreements.map((agreement) => (
                <Card
                  key={agreement.id}
                  className="hover:shadow-lg transition-shadow cursor-pointer group relative overflow-hidden"
                  onClick={() => navigate(`/agreements/${agreement.id}`)}
                >
                  <div className={`absolute top-0 left-0 w-1 h-full ${agreement.priority === 'URGENT' ? 'bg-red-500' :
                    agreement.priority === 'HIGH' ? 'bg-orange-500' :
                      agreement.priority === 'MEDIUM' ? 'bg-blue-500' : 'bg-green-500'
                    }`} />
                  <CardHeader className="pb-4">
                    <div className="flex justify-between items-start mb-2">
                      <Badge variant="secondary" className={getStatusColor(agreement.status)}>
                        {getStatusLabel(agreement.status)}
                      </Badge>
                      {agreement.priority === 'URGENT' && (
                        <Badge variant="destructive" className="flex items-center gap-1">
                          <AlertCircle className="h-3 w-3" /> Urgente
                        </Badge>
                      )}
                    </div>
                    <CardTitle className="line-clamp-1 group-hover:text-primary transition-colors">
                      {agreement.title}
                    </CardTitle>
                    <CardDescription className="line-clamp-2 mt-2">
                      {agreement.description}
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex flex-col gap-3 text-sm text-muted-foreground">
                      <div className="flex items-center gap-2">
                        <Calendar className="h-4 w-4 text-primary/70" />
                        <span>
                          {format(new Date(agreement.due_date), "dd 'de' MMMM", { locale: ptBR })}
                        </span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Users className="h-4 w-4 text-primary/70" />
                        <span>
                          {agreement.agreement_participants[0]?.count || 0} participantes
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            /* Empty State */
            <Card>
              <CardHeader>
                <CardTitle>Nenhum combinado encontrado</CardTitle>
                <CardDescription>
                  {canCreateAgreements
                    ? "Comece criando seu primeiro combinado"
                    : "Você ainda não participa de nenhum combinado"}
                </CardDescription>
              </CardHeader>
              <CardContent>
                {canCreateAgreements && (
                  <Button onClick={() => { console.log("[AgreementsIndex] Criar Primeiro Combinado click"); navigate("/agreements/new"); }}>
                    <Plus className="mr-2 h-4 w-4" />
                    Criar Primeiro Combinado
                  </Button>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      </main>
    </div>
  );
}
