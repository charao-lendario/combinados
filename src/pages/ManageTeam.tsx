import { useState, useEffect } from "react";
import { supabase, createClient } from "@/integrations/supabase/client";
import { useProfile } from "@/hooks/useProfile";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";
import { Loader2, Plus, ArrowLeft } from "lucide-react";
import { useNavigate } from "react-router-dom";

export default function ManageTeam() {
    const [loading, setLoading] = useState(false);
    const [users, setUsers] = useState<any[]>([]);
    const [newUser, setNewUser] = useState({ name: "", email: "", password: "", position: "" });
    const [workspaceId, setWorkspaceId] = useState<string | null>(null);
    const { isAdmin } = useProfile();
    const navigate = useNavigate();

    useEffect(() => {
        fetchWorkspaceAndUsers();
    }, []);

    const fetchWorkspaceAndUsers = async () => {
        try {
            const { data: { user } } = await supabase.auth.getUser();
            if (!user) return;

            const { data: profile } = await supabase
                .from("profiles")
                .select("workspace_id")
                .eq("id", user.id)
                .single();

            // @ts-ignore
            if (profile?.workspace_id) {
                // @ts-ignore
                setWorkspaceId(profile.workspace_id);
                // @ts-ignore
                await fetchUsers(profile.workspace_id);
            } else {
                const email = user.email?.toLowerCase();
                if (email === 'carol.martins@mutumilklaticinios.com.br') {
                    const { data: ws } = await supabase
                        .from('workspaces')
                        .select('id')
                        .eq('slug', 'mutumilk')
                        .maybeSingle();

                    if (ws) {
                        setWorkspaceId(ws.id);
                        await fetchUsers(ws.id);
                        await supabase
                            .from('profiles')
                            .update({ workspace_id: ws.id } as any)
                            .eq('id', user.id);
                    }
                }
            }
        } catch (error) {
            console.error("Error fetching team", error);
        }
    };

    const fetchUsers = async (wsId: string) => {
        const { data: members, error } = await supabase
            .from("team_members")
            .select("*")
            .eq("workspace_id", wsId)
            .order('name');

        if (error) console.error("Error fetching members", error);
        if (members) setUsers(members);
    };

    const handleCreateUser = async (e: React.FormEvent) => {
        e.preventDefault();

        if (!isAdmin) {
            toast.error("Apenas administradores podem cadastrar novos colaboradores.");
            return;
        }

        if (!workspaceId) {
            toast.error("Você não está em um workspace. Tente recarregar a página.");
            return;
        }
        setLoading(true);

        try {
            const tempClient = createClient(
                import.meta.env.VITE_SUPABASE_URL,
                import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY,
                {
                    auth: {
                        persistSession: false,
                        autoRefreshToken: false,
                        detectSessionInUrl: false
                    }
                }
            );

            // 1. Create new user in Auth
            const { data: signUpData, error: signUpError } = await tempClient.auth.signUp({
                email: newUser.email,
                password: newUser.password,
                options: {
                    data: {
                        full_name: newUser.name,
                        position: newUser.position,
                    },
                    emailRedirectTo: window.location.origin
                },
            });

            if (signUpError) throw signUpError;

            if (!signUpData.session && !signUpData.user) {
                throw new Error("O servidor ainda está exigindo confirmação de email.");
            }

            if (signUpData.user) {
                // 2. Update Profile (via tempClient - user updating themselves)
                const updatePayload = {
                    workspace_id: workspaceId,
                    full_name: newUser.name,
                    position: newUser.position,
                    must_change_password: false
                };

                // @ts-ignore
                await tempClient.from("profiles").upsert({
                    id: signUpData.user.id,
                    ...updatePayload
                } as any);

                // @ts-ignore
                await tempClient.from("user_roles").upsert({
                    user_id: signUpData.user.id,
                    role: 'COLABORADOR'
                });

                // 3. Add to Team Members Table (via Main Admin Client)
                const { error: teamError } = await supabase
                    .from("team_members")
                    .insert({
                        workspace_id: workspaceId,
                        user_id: signUpData.user.id,
                        email: newUser.email,
                        name: newUser.name,
                        role: 'COLABORADOR',
                        position: newUser.position
                    });

                if (teamError) console.error("Team members insert error", teamError);
            }

            toast.success("Colaborador cadastrado com sucesso!");
            setNewUser({ name: "", email: "", password: "", position: "" });
            if (workspaceId) fetchUsers(workspaceId);

        } catch (error: any) {
            // Handle "User already registered" by recovering them
            if (error.message?.includes("already registered") || error.status === 400 || error.code === 'user_already_exists') {
                try {
                    const { data: success, error: rpcError } = await supabase.rpc('add_user_to_workspace_v2', {
                        email_input: newUser.email,
                        workspace_id_input: workspaceId,
                        name_input: newUser.name,
                        position_input: newUser.position
                    });

                    if (success) {
                        toast.success("O usuário já existia e foi vinculado ao seu workspace!");
                        setNewUser({ name: "", email: "", password: "", position: "" });
                        if (workspaceId) fetchUsers(workspaceId);
                        return;
                    } else if (rpcError) {
                        toast.error("Usuário existe mas falha ao vincular: " + rpcError.message);
                    } else {
                        toast.error("Usuário existe e não pôde ser vinculado (não encontrado no auth).");
                    }
                } catch (inner) {
                    console.error(inner);
                }
            } else {
                toast.error(error.message || "Erro ao cadastrar user");
            }
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="p-6 space-y-6">
            <div className="flex items-center gap-4">
                <Button variant="ghost" size="icon" onClick={() => navigate("/dashboard")}>
                    <ArrowLeft className="h-5 w-5" />
                </Button>
                <h1 className="text-2xl font-bold">Gestão de Equipe</h1>
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Cadastrar Novo Colaborador</CardTitle>
                </CardHeader>
                <CardContent>
                    <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
                        <div className="space-y-2">
                            <Label>Nome</Label>
                            <Input
                                value={newUser.name}
                                onChange={e => setNewUser({ ...newUser, name: e.target.value })}
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <Label>Email</Label>
                            <Input
                                type="email"
                                value={newUser.email}
                                onChange={e => setNewUser({ ...newUser, email: e.target.value })}
                                required
                            />
                        </div>
                        <div className="space-y-2">
                            <Label>Senha Inicial</Label>
                            <Input
                                type="text"
                                value={newUser.password}
                                onChange={e => setNewUser({ ...newUser, password: e.target.value })}
                                required
                                minLength={6}
                            />
                        </div>
                        <div className="space-y-2">
                            <Label>Cargo</Label>
                            <Input
                                value={newUser.position}
                                onChange={e => setNewUser({ ...newUser, position: e.target.value })}
                                required
                            />
                        </div>
                        <div className="md:col-span-2">
                            <Button type="submit" disabled={loading} className="w-full md:w-auto">
                                {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                                <Plus className="mr-2 h-4 w-4" /> Cadastrar Colaborador
                            </Button>
                        </div>
                    </form>

                    <Table>
                        <TableHeader>
                            <TableRow>
                                <TableHead>Nome</TableHead>
                                <TableHead>Email</TableHead>
                                <TableHead>Cargo</TableHead>
                                <TableHead>Status</TableHead>
                                <TableHead>Ações</TableHead>
                            </TableRow>
                        </TableHeader>
                        <TableBody>
                            {users.map((user) => (
                                <TableRow key={user.user_id}>
                                    <TableCell>{user.name}</TableCell>
                                    <TableCell>{user.email}</TableCell>
                                    <TableCell>{user.position || "-"}</TableCell>
                                    <TableCell>Ativo</TableCell>
                                    <TableCell>
                                        <Button
                                            variant="destructive"
                                            size="sm"
                                            onClick={async () => {
                                                if (confirm("Tem certeza que deseja remover este colaborador?")) {
                                                    const { data: { user: currentUser } } = await supabase.auth.getUser();
                                                    const { data: success, error } = await supabase.rpc('remove_user_from_workspace', {
                                                        target_user_id: user.user_id,
                                                        executor_user_id: currentUser?.id
                                                    });

                                                    if (error || !success) {
                                                        toast.error("Erro ao remover colaborador: " + (error?.message || "Falha desconhecida"));
                                                    } else {
                                                        toast.success("Colaborador removido.");
                                                        if (workspaceId) fetchUsers(workspaceId);
                                                    }
                                                }
                                            }}
                                        >
                                            Remover
                                        </Button>
                                    </TableCell>
                                </TableRow>
                            ))}
                            {users.length === 0 && (
                                <TableRow>
                                    <TableCell colSpan={5} className="text-center">Nenhum colaborador encontrado.</TableCell>
                                </TableRow>
                            )}
                        </TableBody>
                    </Table>
                    <p className="text-sm text-muted-foreground mt-4">
                        Nota: A lista exibe membros ativos do workspace.
                    </p>
                </CardContent>
            </Card>
        </div>
    );
}
