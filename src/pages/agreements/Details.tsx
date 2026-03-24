import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { Badge } from "@/components/ui/badge";
import { format } from "date-fns";
import { ptBR } from "date-fns/locale";
import { Calendar, Clock, Users, CheckCircle2, XCircle, Trash2, ArrowLeft } from "lucide-react";
import { toast } from "sonner";
import {
    AlertDialog,
    AlertDialogAction,
    AlertDialogCancel,
    AlertDialogContent,
    AlertDialogDescription,
    AlertDialogFooter,
    AlertDialogHeader,
    AlertDialogTitle,
    AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogFooter,
    DialogHeader,
    DialogTitle,
    DialogTrigger,
} from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import { FileIcon, Download } from "lucide-react";

export default function AgreementDetails() {
    const { id } = useParams();
    const { user, loading: authLoading } = useAuth();
    const navigate = useNavigate();
    const queryClient = useQueryClient();
    const [responseComment, setResponseComment] = useState("");
    const [actionType, setActionType] = useState<"ACCEPTED" | "REJECTED" | null>(null);
    const [isDialogOpen, setIsDialogOpen] = useState(false);

    useEffect(() => {
        if (!authLoading && !user) {
            navigate("/auth");
        }
    }, [user, authLoading, navigate]);

    const { data: agreement, isLoading } = useQuery({
        queryKey: ["agreement", id],
        queryFn: async () => {
            const API_URL = import.meta.env.VITE_API_URL || '';
            const session = localStorage.getItem('combinados_session');
            const token = session ? JSON.parse(session).access_token : null;
            const res = await fetch(`${API_URL}/api/compound/agreements/${id}/full`, {
                headers: token ? { 'Authorization': `Bearer ${token}` } : {},
            });
            const { data, error } = await res.json();
            if (error) throw error;
            return data;
        },
        enabled: !!id && !!user,
    });

    const updateStatusMutation = useMutation({
        mutationFn: async ({ status, comment }: { status: "ACCEPTED" | "REJECTED", comment?: string }) => {
            if (!user || !agreement) return;

            // Atualizar status do participante
            const { error: participantError } = await supabase
                .from("agreement_participants")
                .update({
                    status,
                    response_date: new Date().toISOString(),
                    rejection_reason: status === "REJECTED" ? comment : null
                })
                .eq("agreement_id", agreement.id)
                .eq("user_id", user.id);

            if (participantError) throw participantError;

            // Adicionar comentário se houver (apenas para aceites, rejeições ficam no rejection_reason)
            if (comment && status === "ACCEPTED") {
                await supabase.from("comments").insert({
                    agreement_id: agreement.id,
                    content: comment,
                    author_id: user.id
                });
            }

            // Notificar o criador
            if (agreement.creator_id !== user.id) {
                await supabase.from("notifications").insert({
                    user_id: agreement.creator_id,
                    type: status === "ACCEPTED" ? "AGREEMENT_ACCEPTED" : "AGREEMENT_REJECTED",
                    title: `Combinado ${status === "ACCEPTED" ? "Aceito" : "Rejeitado"}`,
                    message: status === "ACCEPTED"
                        ? `${user.email} aceitou o combinado "${agreement.title}"`
                        : `${user.email} rejeitou o combinado "${agreement.title}". Justificativa: ${comment}`,
                    related_id: agreement.id,
                    related_type: "agreement"
                });
            }

            // Se todos aceitaram, atualizar status do combinado para IN_PROGRESS
            if (status === "ACCEPTED") {
                const { data: participants } = await supabase
                    .from("agreement_participants")
                    .select("status, user_id")
                    .eq("agreement_id", agreement.id);

                const allAccepted = participants?.every(p => p.status === "ACCEPTED" || (p.user_id === user.id && status === "ACCEPTED"));

                if (allAccepted) {
                    await supabase
                        .from("agreements")
                        .update({ status: "IN_PROGRESS" })
                        .eq("id", agreement.id);
                }
            }
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["agreement", id] });
            toast.success("Resposta enviada com sucesso!");
            setIsDialogOpen(false);
            setResponseComment("");
        },
        onError: (error) => {
            console.error("Erro ao responder:", error);
            toast.error("Erro ao enviar resposta");
        }
    });

    const toggleChecklistItemMutation = useMutation({
        mutationFn: async ({ itemId, isCompleted }: { itemId: string, isCompleted: boolean }) => {
            if (!user) return;

            const { error } = await supabase
                .from("checklist_items")
                .update({
                    is_completed: isCompleted,
                    completed_at: isCompleted ? new Date().toISOString() : null,
                    completed_by_id: isCompleted ? user.id : null
                })
                .eq("id", itemId);

            if (error) throw error;

            // Notificar o criador se o item foi concluído e quem concluiu não é o criador
            if (isCompleted && agreement.creator_id !== user.id) {
                const item = agreement.checklist_items.find((i: any) => i.id === itemId);
                const itemDescription = item ? item.description : "um item";

                await supabase.from("notifications").insert({
                    user_id: agreement.creator_id,
                    type: "CHECKLIST_ITEM_CHECKED",
                    title: "Item de Checklist Concluído",
                    message: `${user.email} concluiu "${itemDescription}" no combinado "${agreement.title}"`,
                    related_id: agreement.id,
                    related_type: "agreement"
                });
            }

            // Verificar se todos os itens foram concluídos para atualizar o status do combinado
            const { data: items } = await supabase
                .from("checklist_items")
                .select("is_completed")
                .eq("agreement_id", agreement.id);

            if (items) {
                const allCompleted = items.every((i) => i.is_completed);

                if (allCompleted && agreement.status !== "COMPLETED") {
                    await supabase
                        .from("agreements")
                        .update({ status: "COMPLETED" })
                        .eq("id", agreement.id);

                    toast.success("Todos os itens concluídos! Combinado finalizado.");
                } else if (!allCompleted && agreement.status === "COMPLETED") {
                    // Reverter para IN_PROGRESS se alguém desmarcar um item
                    await supabase
                        .from("agreements")
                        .update({ status: "IN_PROGRESS" })
                        .eq("id", agreement.id);
                }
            }
        },
        onSuccess: () => {
            queryClient.invalidateQueries({ queryKey: ["agreement", id] });
        },
        onError: (error) => {
            console.error("Erro ao atualizar checklist:", error);
            toast.error("Erro ao atualizar item");
        }
    });

    const deleteMutation = useMutation({
        mutationFn: async () => {
            const { error } = await supabase
                .from("agreements")
                .delete()
                .eq("id", id);

            if (error) throw error;
        },
        onSuccess: () => {
            toast.success("Combinado excluído com sucesso");
            navigate("/agreements");
        },
        onError: (error) => {
            console.error("Erro ao excluir:", error);
            toast.error("Erro ao excluir combinado");
        }
    });

    const handleActionClick = (type: "ACCEPTED" | "REJECTED") => {
        setActionType(type);
        setIsDialogOpen(true);
    };

    const confirmAction = () => {
        if (actionType) {
            updateStatusMutation.mutate({ status: actionType, comment: responseComment });
        }
    };

    if (isLoading || authLoading) {
        return (
            <div className="min-h-screen bg-gradient-to-br from-background via-secondary/5 to-primary/5">
                <Header />
                <main className="container py-8">
                    <Skeleton className="h-12 w-64 mb-8" />
                    <Skeleton className="h-96" />
                </main>
            </div>
        );
    }

    if (!agreement) return <div className="container py-8">Combinado não encontrado</div>;

    const isCreator = user?.id === agreement.creator_id;
    const myParticipation = agreement.agreement_participants.find((p: any) => p.user_id === user?.id);
    const isPending = myParticipation?.status === "PENDING";

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

    const getPriorityLabel = (priority: string) => {
        switch (priority) {
            case "LOW": return "Baixa";
            case "MEDIUM": return "Média";
            case "HIGH": return "Alta";
            case "URGENT": return "Urgente";
            default: return priority;
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-background via-secondary/5 to-primary/5">
            <Header />
            <main className="container py-8 max-w-4xl">
                <Button variant="ghost" className="mb-6" onClick={() => navigate("/agreements")}>
                    <ArrowLeft className="mr-2 h-4 w-4" /> Voltar
                </Button>

                <div className="space-y-6">
                    <div className="flex justify-between items-start">
                        <div>
                            <h1 className="text-3xl font-bold">{agreement.title}</h1>
                            <div className="flex gap-2 mt-2">
                                <Badge>{getStatusLabel(agreement.status)}</Badge>
                            </div>
                        </div>
                        {isCreator && (
                            <AlertDialog>
                                <AlertDialogTrigger asChild>
                                    <Button variant="destructive" size="sm">
                                        <Trash2 className="mr-2 h-4 w-4" /> Excluir
                                    </Button>
                                </AlertDialogTrigger>
                                <AlertDialogContent>
                                    <AlertDialogHeader>
                                        <AlertDialogTitle>Tem certeza?</AlertDialogTitle>
                                        <AlertDialogDescription>
                                            Esta ação não pode ser desfeita. Isso excluirá permanentemente o combinado e todos os dados associados.
                                        </AlertDialogDescription>
                                    </AlertDialogHeader>
                                    <AlertDialogFooter>
                                        <AlertDialogCancel>Cancelar</AlertDialogCancel>
                                        <AlertDialogAction onClick={() => deleteMutation.mutate()} className="bg-destructive text-destructive-foreground hover:bg-destructive/90">
                                            Excluir
                                        </AlertDialogAction>
                                    </AlertDialogFooter>
                                </AlertDialogContent>
                            </AlertDialog>
                        )}
                    </div>

                    <Card>
                        <CardHeader>
                            <CardTitle>Detalhes</CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                            <p className="text-lg">{agreement.description}</p>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4">
                                <div className="flex items-center gap-2">
                                    <Calendar className="h-5 w-5 text-muted-foreground" />
                                    <div>
                                        <p className="text-sm font-medium">Data da Reunião</p>
                                        <p className="text-sm text-muted-foreground">
                                            {format(new Date(agreement.meeting_date), "dd/MM/yyyy HH:mm", { locale: ptBR })}
                                        </p>
                                    </div>
                                </div>
                                <div className="flex items-center gap-2">
                                    <Clock className="h-5 w-5 text-muted-foreground" />
                                    <div>
                                        <p className="text-sm font-medium">Vencimento</p>
                                        <p className="text-sm text-muted-foreground">
                                            {format(new Date(agreement.due_date), "dd/MM/yyyy HH:mm", { locale: ptBR })}
                                        </p>
                                    </div>
                                </div>
                            </div>

                            {/* Tags */}
                            {agreement.tags && agreement.tags.length > 0 && (
                                <div className="flex flex-wrap gap-2 mt-4">
                                    {agreement.tags.map((tag: string, index: number) => (
                                        <Badge key={index} variant="secondary">#{tag}</Badge>
                                    ))}
                                </div>
                            )}
                        </CardContent>
                    </Card>

                    {/* Checklist */}
                    {agreement.checklist_items && agreement.checklist_items.length > 0 && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Checklist</CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-3">
                                {agreement.checklist_items
                                    .filter((item: any) => item.assigned_to_id === user?.id)
                                    .sort((a: any, b: any) => a.order_index - b.order_index)
                                    .map((item: any) => (
                                        <div key={item.id} className="flex items-start gap-3 p-2 rounded hover:bg-secondary/20">
                                            <Checkbox
                                                id={item.id}
                                                checked={item.is_completed}
                                                onCheckedChange={(checked) => toggleChecklistItemMutation.mutate({
                                                    itemId: item.id,
                                                    isCompleted: checked as boolean
                                                })}
                                                disabled={myParticipation?.status !== "ACCEPTED"}
                                            />
                                            <div className="grid gap-1.5 leading-none">
                                                <label
                                                    htmlFor={item.id}
                                                    className={`text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70 ${item.is_completed ? 'line-through text-muted-foreground' : ''}`}
                                                >
                                                    {item.description}
                                                </label>
                                                {item.assigned_to_id && (
                                                    <p className="text-xs text-muted-foreground">
                                                        Atribuído a: {agreement.agreement_participants.find((p: any) => p.user_id === item.assigned_to_id)?.profiles?.full_name || "Alguém"}
                                                    </p>
                                                )}
                                            </div>
                                        </div>
                                    ))}
                                {agreement.checklist_items.filter((item: any) => item.assigned_to_id === user?.id).length === 0 && (
                                    <p className="text-sm text-muted-foreground text-center py-4">
                                        Nenhuma tarefa atribuída a você.
                                    </p>
                                )}
                            </CardContent>
                        </Card>
                    )}

                    {/* Anexos */}
                    {agreement.attachments && agreement.attachments.length > 0 && (
                        <Card>
                            <CardHeader>
                                <CardTitle>Anexos</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <div className="grid gap-4 sm:grid-cols-2">
                                    {agreement.attachments.map((file: any) => (
                                        <AttachmentItem key={file.id} file={file} />
                                    ))}
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* Área de Ação para o Colaborador (e Criador se também for participante) */}
                    {isPending && (
                        <Card className="border-primary/50 bg-primary/5">
                            <CardHeader>
                                <CardTitle>Sua Resposta</CardTitle>
                                <CardDescription>Você precisa aceitar ou rejeitar este combinado</CardDescription>
                            </CardHeader>
                            <CardContent className="flex gap-4">
                                <Button
                                    className="w-full bg-green-600 hover:bg-green-700"
                                    onClick={() => handleActionClick("ACCEPTED")}
                                >
                                    <CheckCircle2 className="mr-2 h-4 w-4" /> Aceitar Combinado
                                </Button>
                                <Button
                                    variant="destructive"
                                    className="w-full"
                                    onClick={() => handleActionClick("REJECTED")}
                                >
                                    <XCircle className="mr-2 h-4 w-4" /> Rejeitar
                                </Button>
                            </CardContent>
                        </Card>
                    )}

                    {isCreator && !myParticipation && (
                        <div className="bg-muted/50 p-4 rounded-lg border border-dashed text-center text-muted-foreground text-sm">
                            Você é o criador deste combinado. Como não se adicionou como participante, não há ações de aceite/rejeição pendentes para você.
                        </div>
                    )}

                    <Card>
                        <CardHeader>
                            <CardTitle>Participantes</CardTitle>
                        </CardHeader>
                        <CardContent>
                            <div className="space-y-4">
                                {agreement.agreement_participants.map((participant: any) => (
                                    <div key={participant.id} className="flex flex-col gap-2 p-3 bg-secondary/50 rounded-lg">
                                        <div className="flex items-center justify-between w-full">
                                            <div className="flex items-center gap-3">
                                                <div className="h-10 w-10 rounded-full bg-primary/10 flex items-center justify-center">
                                                    <span className="font-bold text-primary">
                                                        {participant.profiles?.full_name?.charAt(0) || "?"}
                                                    </span>
                                                </div>
                                                <div>
                                                    <p className="font-medium">{participant.profiles?.full_name}</p>
                                                    <p className="text-sm text-muted-foreground">{participant.profiles?.position}</p>
                                                </div>
                                            </div>
                                            {isCreator && (
                                                <Badge variant={
                                                    participant.status === "ACCEPTED" ? "default" :
                                                        participant.status === "REJECTED" ? "destructive" : "secondary"
                                                }>
                                                    {participant.status === "ACCEPTED" ? "Aceitou" :
                                                        participant.status === "REJECTED" ? "Rejeitou" : "Pendente"}
                                                </Badge>
                                            )}
                                            {!isCreator && (
                                                <Badge variant="outline">Participante</Badge>
                                            )}
                                        </div>

                                        {/* Mostrar motivo da rejeição apenas para o criador */}
                                        {isCreator && participant.status === "REJECTED" && participant.rejection_reason && (
                                            <div className="text-sm text-destructive bg-destructive/10 p-2 rounded mt-1">
                                                <strong>Motivo da rejeição:</strong> {participant.rejection_reason}
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </CardContent>
                    </Card>
                </div>

                <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
                    <DialogContent>
                        <DialogHeader>
                            <DialogTitle>
                                {actionType === "ACCEPTED" ? "Aceitar Combinado" : "Rejeitar Combinado"}
                            </DialogTitle>
                            <DialogDescription>
                                {actionType === "ACCEPTED"
                                    ? "Deseja adicionar algum comentário ao aceitar?"
                                    : "Por favor, informe o motivo da rejeição."}
                            </DialogDescription>
                        </DialogHeader>
                        <div className="py-4">
                            <Textarea
                                placeholder={actionType === "ACCEPTED" ? "Comentário opcional..." : "Motivo da rejeição..."}
                                value={responseComment}
                                onChange={(e) => setResponseComment(e.target.value)}
                            />
                        </div>
                        <DialogFooter>
                            <Button variant="outline" onClick={() => setIsDialogOpen(false)}>Cancelar</Button>
                            <Button
                                onClick={confirmAction}
                                variant={actionType === "REJECTED" ? "destructive" : "default"}
                                disabled={updateStatusMutation.isPending || (actionType === "REJECTED" && !responseComment.trim())}
                            >
                                {updateStatusMutation.isPending ? "Enviando..." : "Confirmar"}
                            </Button>
                        </DialogFooter>
                    </DialogContent>
                </Dialog>
            </main>
        </div>
    );
}

function AttachmentItem({ file }: { file: any }) {
    const [signedUrl, setSignedUrl] = useState<string | null>(null);

    useEffect(() => {
        const getUrl = async () => {
            const { data, error } = await supabase
                .storage
                .from('agreement-attachments')
                .createSignedUrl(file.storage_path, 3600); // 1 hora

            if (data?.signedUrl) {
                setSignedUrl(data.signedUrl);
            } else {
                console.error("Erro ao gerar URL assinada:", error);
            }
        };

        getUrl();
    }, [file.storage_path]);

    return (
        <div className="flex items-center gap-3 p-3 border rounded-lg hover:bg-secondary/10 transition-colors">
            <div className="h-10 w-10 rounded bg-primary/10 flex items-center justify-center">
                <FileIcon className="h-5 w-5 text-primary" />
            </div>
            <div className="flex-1 overflow-hidden">
                <p className="text-sm font-medium truncate">{file.file_name}</p>
                <p className="text-xs text-muted-foreground">
                    {(file.file_size / 1024).toFixed(1)} KB
                </p>
            </div>
            {signedUrl ? (
                <Button variant="ghost" size="icon" asChild>
                    <a href={signedUrl} target="_blank" rel="noopener noreferrer" download={file.file_name}>
                        <Download className="h-4 w-4" />
                    </a>
                </Button>
            ) : (
                <Button variant="ghost" size="icon" disabled>
                    <Download className="h-4 w-4 opacity-50" />
                </Button>
            )}
        </div>
    );
}
