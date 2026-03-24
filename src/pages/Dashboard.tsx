import { useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useProfile } from "@/hooks/useProfile";
import { useRealtimeNotifications } from "@/hooks/useRealtimeNotifications";
import { supabase } from "@/integrations/supabase/client";
import { Header } from "@/components/layout/Header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Plus, CheckSquare, FileText, AlertCircle, Calendar, XCircle } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { Badge } from "@/components/ui/badge";

export default function Dashboard() {
  const { user, loading: authLoading } = useAuth();
  const { canCreateAgreements, isColaborador, isAdmin, loading: profileLoading } = useProfile();
  const navigate = useNavigate();

  // Hook para notificações em tempo real
  useRealtimeNotifications(user?.id);

  const { data: agreements, isLoading: agreementsLoading } = useQuery({
    queryKey: ["dashboard-agreements", user?.id],
    queryFn: async () => {
      if (!user) return [];

      // 1. Buscar IDs dos combinados onde sou participante
      const { data: participations } = await supabase
        .from('agreement_participants')
        .select('agreement_id, status')
        .eq('user_id', user.id);

      const participationIds = participations?.map(p => p.agreement_id) || [];
      const participationStatusMap = new Map(participations?.map(p => [p.agreement_id, p.status]));

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

      // Anexar meu status aos combinados
      return data.map((agreement: any) => ({
        ...agreement,
        my_status: participationStatusMap.get(agreement.id)
      }));
    },
    enabled: !!user,
  });

  const loading = authLoading || profileLoading || agreementsLoading;

  useEffect(() => {
    if (!authLoading && !user) {
      navigate("/auth");
    }
  }, [user, authLoading, navigate]);

  if (loading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-background via-secondary/5 to-primary/5">
        <Header />
        <main className="container py-8">
          <div className="space-y-8">
            <Skeleton className="h-12 w-64" />
            <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
              {[1, 2, 3, 4].map((i) => (
                <Skeleton key={i} className="h-32" />
              ))}
            </div>
          </div>
        </main>
      </div>
    );
  }

  if (!user) return null;

  // Calcular estatísticas
  const pendingCount = agreements?.filter(a => a.status === 'PENDING').length || 0;
  const inProgressCount = agreements?.filter(a => a.status === 'IN_PROGRESS' || a.status === 'ACCEPTED').length || 0;
  const completedCount = agreements?.filter(a => a.status === 'COMPLETED').length || 0;
  const rejectedCount = agreements?.filter(a => a.status === 'REJECTED' || a.my_status === 'REJECTED').length || 0;

  const totalAgreements = agreements?.length || 0;
  const completionRate = totalAgreements > 0
    ? Math.round((completedCount / totalAgreements) * 100)
    : 0;

  const getStatusLabel = (status: string) => {
    switch (status) {
      case "COMPLETED": return "Concluído";
      case "IN_PROGRESS": return "Em Andamento";
      case "PENDING": return "Pendente";
      case "OVERDUE": return "Atrasado";
      case "DRAFT": return "Rascunho";
      case "ACCEPTED": return "Aceito";
      case "REJECTED": return "Rejeitado";
      case "CANCELLED": return "Cancelado";
      default: return status;
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case "COMPLETED": return "bg-green-500/10 text-green-500 hover:bg-green-500/20";
      case "IN_PROGRESS": return "bg-blue-500/10 text-blue-500 hover:bg-blue-500/20";
      case "PENDING": return "bg-yellow-500/10 text-yellow-500 hover:bg-yellow-500/20";
      case "OVERDUE": return "bg-red-500/10 text-red-500 hover:bg-red-500/20";
      default: return "bg-secondary text-secondary-foreground";
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-background via-secondary/5 to-primary/5">
      <Header />

      {/* Main Content */}
      <main className="container py-8">
        <div className="space-y-8">
          {/* Welcome Section */}
          <div className="animate-in fade-in slide-in-from-bottom-4 duration-500">
            <h2 className="text-3xl font-bold tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-foreground to-foreground/70">
              Bem-vindo de volta!
            </h2>
            <p className="text-muted-foreground mt-1">
              Aqui está um resumo dos seus combinados
            </p>
          </div>

          {/* Stats Cards */}
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-5">
            <Card className="hover:shadow-lg transition-all duration-300 hover:scale-[1.02] border-l-4 border-l-yellow-500 bg-card/50 backdrop-blur-sm">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">
                  Pendentes
                </CardTitle>
                <AlertCircle className="h-4 w-4 text-yellow-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{pendingCount}</div>
                <p className="text-xs text-muted-foreground">
                  Aguardando resposta
                </p>
              </CardContent>
            </Card>

            <Card className="hover:shadow-lg transition-all duration-300 hover:scale-[1.02] border-l-4 border-l-blue-500 bg-card/50 backdrop-blur-sm">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">
                  Em Andamento
                </CardTitle>
                <FileText className="h-4 w-4 text-blue-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{inProgressCount}</div>
                <p className="text-xs text-muted-foreground">
                  Combinados ativos
                </p>
              </CardContent>
            </Card>

            <Card className="hover:shadow-lg transition-all duration-300 hover:scale-[1.02] border-l-4 border-l-green-500 bg-card/50 backdrop-blur-sm">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">
                  Concluídos
                </CardTitle>
                <CheckSquare className="h-4 w-4 text-green-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{completedCount}</div>
                <p className="text-xs text-muted-foreground">
                  Total finalizado
                </p>
              </CardContent>
            </Card>

            <Card className="hover:shadow-lg transition-all duration-300 hover:scale-[1.02] border-l-4 border-l-red-500 bg-card/50 backdrop-blur-sm">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">
                  Rejeitados
                </CardTitle>
                <XCircle className="h-4 w-4 text-red-500" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{rejectedCount}</div>
                <p className="text-xs text-muted-foreground">
                  Recusados
                </p>
              </CardContent>
            </Card>

            <Card className="hover:shadow-lg transition-all duration-300 hover:scale-[1.02] border-l-4 border-l-primary bg-card/50 backdrop-blur-sm">
              <CardHeader className="flex flex-row items-center justify-between pb-2">
                <CardTitle className="text-sm font-medium">
                  Taxa de Conclusão
                </CardTitle>
                <CheckSquare className="h-4 w-4 text-primary" />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{completionRate}%</div>
                <p className="text-xs text-muted-foreground">
                  Do total de combinados
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Quick Actions */}
          <Card className="bg-card/50 backdrop-blur-sm border-primary/20">
            <CardHeader>
              <CardTitle>Ações Rápidas</CardTitle>
              <CardDescription>
                {canCreateAgreements
                  ? "Comece criando seu primeiro combinado"
                  : "Acesse seus combinados recebidos"}
              </CardDescription>
            </CardHeader>
            <CardContent className="flex flex-wrap gap-4">
              <Button onClick={() => navigate("/agreements")} variant="outline" className="hover:bg-secondary hover:text-secondary-foreground transition-colors">
                <FileText className="mr-2 h-4 w-4" />
                Ver Meus Combinados
              </Button>
              {canCreateAgreements && (
                <Button onClick={() => navigate("/agreements/new")} className="bg-primary text-primary-foreground hover:bg-primary/90 shadow-md hover:shadow-lg transition-all">
                  <Plus className="mr-2 h-4 w-4" />
                  Criar Novo Combinado
                </Button>
              )}
              {isAdmin && (
                <Button onClick={() => navigate("/team")} variant="secondary" className="shadow-md hover:shadow-lg transition-all">
                  <Plus className="mr-2 h-4 w-4" />
                  Gerenciar Equipe
                </Button>
              )}
            </CardContent>
          </Card>

          {/* Recent Agreements */}
          <Card className="bg-card/50 backdrop-blur-sm">
            <CardHeader>
              <CardTitle>Combinados Recentes</CardTitle>
              <CardDescription>
                Seus últimos combinados e atualizações
              </CardDescription>
            </CardHeader>
            <CardContent>
              {agreements && agreements.length > 0 ? (
                <div className="space-y-4">
                  {agreements.slice(0, 5).map((agreement: any) => (
                    <div
                      key={agreement.id}
                      className="flex items-center justify-between p-4 border rounded-lg hover:bg-secondary/50 cursor-pointer transition-all duration-200 hover:border-primary/50 group"
                      onClick={() => navigate(`/agreements/${agreement.id}`)}
                    >
                      <div className="space-y-1">
                        <p className="font-medium leading-none group-hover:text-primary transition-colors">{agreement.title}</p>
                        <div className="flex items-center gap-2 text-sm text-muted-foreground">
                          <Calendar className="h-3 w-3" />
                          <span>
                            {format(new Date(agreement.created_at), "dd 'de' MMMM", { locale: ptBR })}
                          </span>
                        </div>
                      </div>
                      <Badge variant="secondary" className={`${getStatusColor(agreement.status)} transition-transform group-hover:scale-105`}>
                        {getStatusLabel(agreement.status)}
                      </Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-12 text-muted-foreground">
                  Nenhum combinado encontrado.
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}
