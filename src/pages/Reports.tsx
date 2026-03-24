import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useProfile } from "@/hooks/useProfile";
import { supabase } from "@/integrations/supabase/client";
import { Header } from "@/components/layout/Header";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { FileText, Download, FileSpreadsheet } from "lucide-react";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import jsPDF from "jspdf";
import autoTable from "jspdf-autotable";
import { toast } from "sonner";

export default function Reports() {
    const { user, loading: authLoading } = useAuth();
    const { isAdmin, loading: profileLoading, profile } = useProfile();
    const navigate = useNavigate();

    useEffect(() => {
        if (!authLoading && !user) {
            navigate("/auth");
        }
    }, [user, authLoading, navigate]);

    const [statusFilter, setStatusFilter] = useState<string>("ALL");
    const [participantFilter, setParticipantFilter] = useState<string>("");

    const { data: agreements, isLoading } = useQuery({
        queryKey: ["reports-agreements", user?.id, isAdmin],
        queryFn: async () => {
            if (!user) return [];

            const API_URL = import.meta.env.VITE_API_URL || '';
            const session = localStorage.getItem('combinados_session');
            const token = session ? JSON.parse(session).access_token : null;
            const res = await fetch(`${API_URL}/api/compound/reports/agreements`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
                },
                body: JSON.stringify({}),
            });
            const { data, error } = await res.json();

            if (error) {
                console.error("Erro ao buscar relatórios:", error);
                throw error;
            }

            // Fallback Frontend Filter for Workspace Isolation
            // If RLS allows read (e.g. public policy), we hide it here.
            // We need the current user's workspace ID to compare.
            // We can get it from useProfile but it's not strictly passed to this async function scope easily without prop or closure.
            // But we can filter where creator.workspace_id matches our profile.workspace_id if available.

            return data;
        },
        enabled: !!user,
    });

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

    const filteredAgreements = agreements?.filter(agreement => {
        // Filter by Workspace (Frontend Fallback)
        if (profile?.workspace_id) {
            // @ts-ignore
            const creatorWorkspaceId = agreement.creator?.workspace_id;

            // If creator has a workspace ID and it's different from mine, hide it.
            // If creator has NO workspace ID (legacy data), hide it if I am in a specific workspace (Mutumilk).
            if (creatorWorkspaceId && creatorWorkspaceId !== profile.workspace_id) {
                return false;
            }
            if (!creatorWorkspaceId && profile.workspace_id) {
                // Hide legacy/global data from specific workspace users
                return false;
            }
        }

        // Filter by Status
        if (statusFilter !== "ALL") {
            if (agreement.status !== statusFilter) return false;
        }

        // Filter by Participant
        if (participantFilter.trim()) {
            const searchTerm = participantFilter.toLowerCase();
            const hasParticipant = agreement.agreement_participants.some((p: any) =>
                p.profiles?.full_name?.toLowerCase().includes(searchTerm)
            );
            if (!hasParticipant) return false;
        }

        return true;
    }) || [];

    const generatePDF = () => {
        if (!filteredAgreements.length) {
            toast.error("Nenhum dado para exportar com os filtros atuais.");
            return;
        }

        const doc = new jsPDF();

        doc.setFontSize(18);
        doc.text("Relatório de Combinados", 14, 22);
        doc.setFontSize(11);
        doc.text(`Gerado em: ${format(new Date(), "dd/MM/yyyy HH:mm")}`, 14, 30);

        if (statusFilter !== "ALL") {
            doc.text(`Filtro de Status: ${getStatusLabel(statusFilter)}`, 14, 36);
        }

        const tableData = filteredAgreements.map(agreement => {
            const participantsInfo = agreement.agreement_participants
                .map((p: any) => {
                    let info = `${p.profiles?.full_name} (${getStatusLabel(p.status)})`;
                    if (p.status === 'REJECTED' && p.rejection_reason) {
                        info += ` - Motivo: ${p.rejection_reason}`;
                    }
                    return info;
                })
                .join('\n');

            return [
                agreement.title,
                getStatusLabel(agreement.status),
                format(new Date(agreement.created_at), "dd/MM/yyyy"),
                format(new Date(agreement.due_date), "dd/MM/yyyy"),
                participantsInfo
            ];
        });

        autoTable(doc, {
            head: [['Título', 'Status', 'Criado em', 'Vencimento', 'Participantes']],
            body: tableData,
            startY: 45,
            styles: { fontSize: 8, cellPadding: 2 },
            columnStyles: {
                0: { cellWidth: 40 }, // Título
                4: { cellWidth: 80 }  // Participantes
            }
        });

        doc.save(`relatorio_combinados_${format(new Date(), "yyyyMMdd_HHmm")}.pdf`);
        toast.success("PDF gerado com sucesso!");
    };

    const generateCSV = () => {
        if (!filteredAgreements.length) {
            toast.error("Nenhum dado para exportar com os filtros atuais.");
            return;
        }

        const headers = ["Título", "Status", "Criado em", "Vencimento", "Participantes"];
        const rows = filteredAgreements.map(agreement => {
            const participantsInfo = agreement.agreement_participants
                .map((p: any) => {
                    let info = `${p.profiles?.full_name} (${getStatusLabel(p.status)})`;
                    if (p.status === 'REJECTED' && p.rejection_reason) {
                        info += ` - Motivo: ${p.rejection_reason}`;
                    }
                    return info;
                })
                .join('; ');

            return [
                `"${agreement.title.replace(/"/g, '""')}"`,
                `"${getStatusLabel(agreement.status)}"`,
                `"${format(new Date(agreement.created_at), "dd/MM/yyyy")}"`,
                `"${format(new Date(agreement.due_date), "dd/MM/yyyy")}"`,
                `"${participantsInfo.replace(/"/g, '""')}"`
            ];
        });

        const csvContent = [
            headers.join(','),
            ...rows.map(r => r.join(','))
        ].join('\n');

        const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
        const link = document.createElement('a');
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', `relatorio_combinados_${format(new Date(), "yyyyMMdd_HHmm")}.csv`);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        toast.success("CSV gerado com sucesso!");
    };

    if (isLoading || authLoading) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-background via-secondary/5 to-primary/5">
                <Header />
                <main className="container py-8">
                    <div className="text-center">Carregando relatório...</div>
                </main>
            </div>
        );
    }

    return (
        <div className="min-h-screen bg-gradient-to-br from-background via-secondary/5 to-primary/5">
            <Header />
            <main className="container py-8">
                <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
                    <div>
                        <h1 className="text-3xl font-bold">Relatórios</h1>
                        <p className="text-muted-foreground">
                            Visualize e exporte o status dos seus combinados
                        </p>
                    </div>
                    <div className="flex gap-2">
                        <Button onClick={generateCSV} variant="outline">
                            <FileSpreadsheet className="mr-2 h-4 w-4" />
                            Exportar CSV
                        </Button>
                        <Button onClick={generatePDF}>
                            <FileText className="mr-2 h-4 w-4" />
                            Exportar PDF
                        </Button>
                    </div>
                </div>

                <Card className="mb-6">
                    <CardHeader>
                        <CardTitle>Filtros</CardTitle>
                    </CardHeader>
                    <CardContent className="flex flex-col md:flex-row gap-4">
                        <div className="w-full md:w-1/3">
                            <label className="text-sm font-medium mb-2 block">Status</label>
                            <Select value={statusFilter} onValueChange={setStatusFilter}>
                                <SelectTrigger>
                                    <SelectValue placeholder="Selecione o status" />
                                </SelectTrigger>
                                <SelectContent>
                                    <SelectItem value="ALL">Todos</SelectItem>
                                    <SelectItem value="COMPLETED">Concluídos</SelectItem>
                                    <SelectItem value="IN_PROGRESS">Em Andamento</SelectItem>
                                    <SelectItem value="PENDING">Pendente</SelectItem>
                                    <SelectItem value="OVERDUE">Atrasado</SelectItem>
                                    <SelectItem value="DRAFT">Rascunho</SelectItem>
                                    <SelectItem value="ACCEPTED">Aceito</SelectItem>
                                    <SelectItem value="REJECTED">Rejeitado</SelectItem>
                                    <SelectItem value="CANCELLED">Cancelado</SelectItem>
                                </SelectContent>
                            </Select>
                        </div>
                        <div className="w-full md:w-1/3">
                            <label className="text-sm font-medium mb-2 block">Participante</label>
                            <Input
                                placeholder="Buscar por nome..."
                                value={participantFilter}
                                onChange={(e) => setParticipantFilter(e.target.value)}
                            />
                        </div>
                    </CardContent>
                </Card>

                <Card>
                    <CardHeader>
                        <CardTitle>Resultados ({filteredAgreements.length})</CardTitle>
                        <CardDescription>
                            Lista filtrada de combinados
                        </CardDescription>
                    </CardHeader>
                    <CardContent>
                        <div className="rounded-md border">
                            <Table>
                                <TableHeader>
                                    <TableRow>
                                        <TableHead>Título</TableHead>
                                        <TableHead>Status</TableHead>
                                        <TableHead>Criado em</TableHead>
                                        <TableHead>Vencimento</TableHead>
                                        <TableHead>Participantes</TableHead>
                                    </TableRow>
                                </TableHeader>
                                <TableBody>
                                    {filteredAgreements.length > 0 ? (
                                        filteredAgreements.map((agreement) => (
                                            <TableRow key={agreement.id}>
                                                <TableCell className="font-medium">{agreement.title}</TableCell>
                                                <TableCell>{getStatusLabel(agreement.status)}</TableCell>
                                                <TableCell>{format(new Date(agreement.created_at), "dd/MM/yyyy")}</TableCell>
                                                <TableCell>{format(new Date(agreement.due_date), "dd/MM/yyyy")}</TableCell>
                                                <TableCell className="text-sm">
                                                    {agreement.agreement_participants.map((p: any) => (
                                                        <div key={p.id} className="mb-1 last:mb-0">
                                                            <span className={
                                                                p.status === 'ACCEPTED' ? 'text-green-600' :
                                                                    p.status === 'REJECTED' ? 'text-red-600' :
                                                                        'text-muted-foreground'
                                                            }>
                                                                {p.profiles?.full_name} - {getStatusLabel(p.status)}
                                                            </span>
                                                            {p.status === 'REJECTED' && p.rejection_reason && (
                                                                <div className="text-xs text-red-500 pl-2">
                                                                    Motivo: {p.rejection_reason}
                                                                </div>
                                                            )}
                                                        </div>
                                                    ))}
                                                </TableCell>
                                            </TableRow>
                                        ))
                                    ) : (
                                        <TableRow>
                                            <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                                                Nenhum dado encontrado com os filtros selecionados.
                                            </TableCell>
                                        </TableRow>
                                    )}
                                </TableBody>
                            </Table>
                        </div>
                    </CardContent>
                </Card>
            </main>
        </div>
    );
}
