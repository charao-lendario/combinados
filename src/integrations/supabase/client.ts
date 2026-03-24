// Custom API client that replaces Supabase client
// Provides the same interface so minimal frontend changes are needed

const API_URL = import.meta.env.VITE_API_URL || '';

// ============================================
// Token Management
// ============================================
function getToken(): string | null {
  const session = localStorage.getItem('combinados_session');
  if (!session) return null;
  try {
    return JSON.parse(session).access_token;
  } catch {
    return null;
  }
}

function getSession() {
  const session = localStorage.getItem('combinados_session');
  if (!session) return null;
  try {
    return JSON.parse(session);
  } catch {
    return null;
  }
}

function saveSession(session: any) {
  localStorage.setItem('combinados_session', JSON.stringify(session));
}

function clearSession() {
  localStorage.removeItem('combinados_session');
}

function headers() {
  const token = getToken();
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  if (token) h['Authorization'] = `Bearer ${token}`;
  return h;
}

// ============================================
// Auth state change listeners
// ============================================
type AuthChangeCallback = (event: string, session: any) => void;
const authListeners: Set<AuthChangeCallback> = new Set();

function notifyAuthChange(event: string, session: any) {
  authListeners.forEach(cb => {
    try { cb(event, session); } catch (e) { console.error('Auth listener error:', e); }
  });
}

// ============================================
// Auth Module
// ============================================
const auth = {
  async getSession() {
    const session = getSession();
    if (!session) return { data: { session: null }, error: null };

    try {
      const res = await fetch(`${API_URL}/api/auth/session`, { headers: headers() });
      const json = await res.json();
      if (json.error || !json.data?.session) {
        clearSession();
        return { data: { session: null }, error: null };
      }
      return { data: { session: { ...session, user: json.data.session.user } }, error: null };
    } catch {
      return { data: { session }, error: null };
    }
  },

  async signInWithPassword({ email, password }: { email: string; password: string }) {
    const res = await fetch(`${API_URL}/api/auth/signin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const json = await res.json();
    if (json.error) return { data: { user: null, session: null }, error: json.error };

    saveSession(json.data.session);
    notifyAuthChange('SIGNED_IN', json.data.session);
    return { data: json.data, error: null };
  },

  async signUp({ email, password, options }: { email: string; password: string; options?: any }) {
    const res = await fetch(`${API_URL}/api/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, options }),
    });
    const json = await res.json();
    if (json.error) return { data: { user: null, session: null }, error: json.error };
    return { data: json.data, error: null };
  },

  async signOut() {
    try {
      await fetch(`${API_URL}/api/auth/signout`, {
        method: 'POST',
        headers: headers(),
      });
    } catch { /* ignore */ }
    clearSession();
    notifyAuthChange('SIGNED_OUT', null);
    return { error: null };
  },

  async getUser() {
    const res = await fetch(`${API_URL}/api/auth/user`, { headers: headers() });
    const json = await res.json();
    if (json.error) return { data: { user: null }, error: json.error };
    return { data: json.data, error: null };
  },

  async updateUser({ password }: { password?: string }) {
    const res = await fetch(`${API_URL}/api/auth/user`, {
      method: 'PUT',
      headers: headers(),
      body: JSON.stringify({ password }),
    });
    const json = await res.json();
    if (json.error) return { data: { user: null }, error: json.error };
    return { data: json.data, error: null };
  },

  onAuthStateChange(callback: AuthChangeCallback) {
    authListeners.add(callback);
    // Fire initial event
    const session = getSession();
    if (session) {
      setTimeout(() => callback('INITIAL_SESSION', session), 0);
    }
    return {
      data: {
        subscription: {
          unsubscribe: () => { authListeners.delete(callback); },
        },
      },
    };
  },
};

// ============================================
// Query Builder (replaces supabase.from())
// ============================================

interface Filter {
  column: string;
  op: string;
  value: any;
}

interface OrderBy {
  column: string;
  ascending: boolean;
}

class QueryBuilder {
  private table: string;
  private _columns: string = '*';
  private _filters: Filter[] = [];
  private _order: OrderBy[] = [];
  private _limit: number | null = null;
  private _single: boolean = false;
  private _count: string | null = null;
  private _orFilter: string | null = null;
  private _operation: 'select' | 'insert' | 'update' | 'delete' | 'upsert' = 'select';
  private _data: any = null;
  private _onConflict: string | string[] | null = null;
  private _returning: string | null = null;

  constructor(table: string) {
    this.table = table;
  }

  select(columns?: string, options?: { count?: string }) {
    this._operation = 'select';
    this._columns = columns || '*';
    if (options?.count) this._count = options.count;
    return this;
  }

  insert(data: any) {
    this._operation = 'insert';
    this._data = data;
    return this;
  }

  update(data: any) {
    this._operation = 'update';
    this._data = data;
    return this;
  }

  delete() {
    this._operation = 'delete';
    return this;
  }

  upsert(data: any, options?: { onConflict?: string }) {
    this._operation = 'upsert';
    this._data = data;
    if (options?.onConflict) this._onConflict = options.onConflict.split(',');
    return this;
  }

  eq(column: string, value: any) {
    this._filters.push({ column, op: 'eq', value });
    return this;
  }

  neq(column: string, value: any) {
    this._filters.push({ column, op: 'neq', value });
    return this;
  }

  in(column: string, values: any[]) {
    this._filters.push({ column, op: 'in', value: values });
    return this;
  }

  is(column: string, value: any) {
    this._filters.push({ column, op: 'is', value });
    return this;
  }

  or(filter: string) {
    this._orFilter = filter;
    return this;
  }

  order(column: string, options?: { ascending?: boolean }) {
    this._order.push({ column, ascending: options?.ascending !== false });
    return this;
  }

  limit(n: number) {
    this._limit = n;
    return this;
  }

  single() {
    this._single = true;
    return this._execute();
  }

  // For chaining .select() after .insert()
  private _selectAfterMutation = false;

  maybeSingle() {
    this._single = true;
    return this._execute();
  }

  async then(resolve: (value: any) => void, reject?: (reason: any) => void) {
    try {
      const result = await this._execute();
      resolve(result);
    } catch (err) {
      if (reject) reject(err);
    }
  }

  private async _execute(): Promise<any> {
    const endpoint = `${API_URL}/api/db/${this.table}/${this._operation}`;

    let body: any = {};

    switch (this._operation) {
      case 'select':
        body = {
          columns: this._columns,
          filters: this._filters,
          order: this._order.length > 0 ? this._order : undefined,
          limit: this._limit,
          single: this._single,
          count: this._count,
          or: this._orFilter,
        };
        break;
      case 'insert':
        body = {
          data: this._data,
          returning: this._single ? 'single' : undefined,
        };
        break;
      case 'update':
        body = { data: this._data, filters: this._filters };
        break;
      case 'delete':
        body = { filters: this._filters };
        break;
      case 'upsert':
        body = {
          data: this._data,
          onConflict: this._onConflict,
        };
        break;
    }

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify(body),
      });
      const json = await res.json();
      return json;
    } catch (err: any) {
      return { data: null, error: { message: err.message } };
    }
  }
}

// Make QueryBuilder thenable so it works with await
// We need the select() call to return a chainable that auto-executes
class TableRef {
  private table: string;

  constructor(table: string) {
    this.table = table;
  }

  select(columns?: string, options?: { count?: string }): QueryBuilder {
    const qb = new QueryBuilder(this.table);
    qb.select(columns, options);
    return qb;
  }

  insert(data: any): QueryBuilder {
    const qb = new QueryBuilder(this.table);
    qb.insert(data);
    return qb;
  }

  update(data: any): QueryBuilder {
    const qb = new QueryBuilder(this.table);
    qb.update(data);
    return qb;
  }

  delete(): QueryBuilder {
    const qb = new QueryBuilder(this.table);
    qb.delete();
    return qb;
  }

  upsert(data: any, options?: { onConflict?: string }): QueryBuilder {
    const qb = new QueryBuilder(this.table);
    qb.upsert(data, options);
    return qb;
  }
}

// ============================================
// Storage Module
// ============================================
function storageFrom(bucket: string) {
  return {
    async upload(filePath: string, file: File) {
      const formData = new FormData();
      formData.append('file', file);
      formData.append('bucket', bucket);
      formData.append('path', filePath);

      const token = getToken();
      const res = await fetch(`${API_URL}/api/storage/upload`, {
        method: 'POST',
        headers: token ? { 'Authorization': `Bearer ${token}` } : {},
        body: formData,
      });
      const json = await res.json();
      return json;
    },

    async createSignedUrl(path: string, _expiresIn: number) {
      const res = await fetch(`${API_URL}/api/storage/signed-url`, {
        method: 'POST',
        headers: headers(),
        body: JSON.stringify({ path }),
      });
      const json = await res.json();
      if (json.data?.signedUrl) {
        json.data.signedUrl = `${API_URL}${json.data.signedUrl}`;
      }
      return json;
    },
  };
}

// ============================================
// RPC Module
// ============================================
async function rpc(fn: string, params: any = {}) {
  const res = await fetch(`${API_URL}/api/rpc/${fn}`, {
    method: 'POST',
    headers: headers(),
    body: JSON.stringify(params),
  });
  return await res.json();
}

// ============================================
// Realtime (no-op stubs - realtime requires websockets, polling as fallback)
// ============================================
function channel(_name: string) {
  const channelObj = {
    on: (_event: string, _config: any, _callback?: any) => channelObj,
    subscribe: (_callback?: any) => channelObj,
  };
  return channelObj;
}

function removeChannel(_channel: any) {
  // no-op
}

// ============================================
// Export Supabase-compatible client
// ============================================
export const supabase = {
  auth,
  from: (table: string) => new TableRef(table),
  storage: { from: storageFrom },
  rpc,
  channel,
  removeChannel,
};

// Re-export createClient for ManageTeam.tsx compatibility
export function createClient(_url: string, _key: string) {
  return supabase;
}
