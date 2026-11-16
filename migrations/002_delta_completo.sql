-- DELTA · Instalación/actualización de la base de datos en Supabase.
-- Ejecutar una vez en SQL Editor. Hacer copia de seguridad antes de modificar un proyecto existente.
-- Todos los importes se expresan en pesos colombianos (COP).
create extension if not exists pgcrypto;

create table if not exists public.profiles (
 id uuid primary key references auth.users(id) on delete cascade,
 role text not null default 'CLIENTE' check (role in ('CLIENTE','ADMIN')),
 full_name text,
 created_at timestamptz not null default now()
);
create or replace function public.delta_crear_perfil() returns trigger
language plpgsql security definer set search_path = public as $$
begin
 insert into public.profiles(id, role, full_name)
 values(new.id, 'CLIENTE', coalesce(new.raw_user_meta_data->>'full_name',''))
 on conflict(id) do nothing;
 return new;
end $$;
drop trigger if exists delta_usuario_registrado on auth.users;
create trigger delta_usuario_registrado after insert on auth.users
for each row execute function public.delta_crear_perfil();
insert into public.profiles(id,role,full_name)
select id,'CLIENTE',coalesce(raw_user_meta_data->>'full_name','') from auth.users
on conflict(id) do nothing;

create or replace function public.delta_es_admin() returns boolean
language sql stable security definer set search_path = public
as $$ select exists (select 1 from public.profiles where id = (select auth.uid()) and role='ADMIN') $$;
revoke all on function public.delta_es_admin() from public;
grant execute on function public.delta_es_admin() to authenticated, service_role;

create table if not exists public.productos (
 id uuid primary key default gen_random_uuid(),
 name text not null,
 brand text not null default 'DELTA',
 family text not null default 'Sin clasificar',
 description text not null default '',
 price numeric(12,2) not null check(price>=0),
 stock integer not null default 0 check(stock>=0),
 image_url text,
 created_at timestamptz not null default now()
);
alter table public.productos add column if not exists image_url text;

create table if not exists public.pedidos (
 id uuid primary key default gen_random_uuid(),
 codigo text not null unique,
 usuario_id uuid references auth.users(id) on delete set null,
 cliente_nombre text not null,
 cliente_email text,
 cliente_telefono text not null,
 direccion text not null,
 total numeric(12,2) not null default 0,
 estado text not null default 'nuevo' check (estado in ('nuevo','pagado','entregado','cancelado')),
 whatsapp_confirmado boolean not null default false,
 whatsapp_confirmado_at timestamptz,
 notas_admin text,
 created_at timestamptz not null default now()
);
alter table public.pedidos add column if not exists usuario_id uuid references auth.users(id) on delete set null;
alter table public.pedidos add column if not exists cliente_email text;
alter table public.pedidos add column if not exists notas_admin text;
alter table public.pedidos add column if not exists whatsapp_confirmado boolean not null default false;
alter table public.pedidos add column if not exists whatsapp_confirmado_at timestamptz;
create index if not exists idx_delta_pedidos_usuario on public.pedidos(usuario_id,created_at desc);

create table if not exists public.pedido_items (
 id uuid primary key default gen_random_uuid(),
 pedido_id uuid not null references public.pedidos(id) on delete cascade,
 producto_id uuid references public.productos(id) on delete set null,
 nombre text not null,
 precio numeric(12,2) not null,
 cantidad integer not null check(cantidad>0),
 subtotal numeric(12,2) not null
);
create index if not exists idx_delta_items_pedido on public.pedido_items(pedido_id);

create table if not exists public.pedido_historial (
 id uuid primary key default gen_random_uuid(),
 pedido_id uuid not null references public.pedidos(id) on delete cascade,
 estado text not null,
 nota text,
 creado_at timestamptz not null default now()
);
create index if not exists idx_delta_historial_pedido on public.pedido_historial(pedido_id);

create table if not exists public.puntos_movimientos (
 id uuid primary key default gen_random_uuid(),
 usuario_id uuid not null references auth.users(id) on delete cascade,
 pedido_id uuid not null references public.pedidos(id),
 tipo text not null check(tipo in ('GANADOS','REVERSADOS')),
 puntos integer not null,
 descripcion text not null,
 created_at timestamptz not null default now(),
 unique(pedido_id,tipo)
);
create index if not exists idx_delta_puntos_usuario on public.puntos_movimientos(usuario_id,created_at desc);

-- Sustituir las políticas anteriores en estas tablas es importante: las políticas RLS
-- son OR entre sí, así que una antigua política pública podría dejar datos expuestos.
-- Si compartes estas tablas con otros sistemas, revisa la migración antes de ejecutarla.
do $$ declare x record; begin
  for x in select schemaname, tablename, policyname from pg_policies
    where schemaname='public' and tablename in
      ('profiles','productos','pedidos','pedido_items','pedido_historial','puntos_movimientos')
  loop
    execute format('drop policy if exists %I on %I.%I', x.policyname, x.schemaname, x.tablename);
  end loop;
end $$;

-- El perfil es visible al propietario; NUNCA puede elevar su propio rol.
alter table public.profiles enable row level security;
drop policy if exists delta_profile_read on public.profiles;
create policy delta_profile_read on public.profiles for select to authenticated
using (id=(select auth.uid()) or (select public.delta_es_admin()));
drop policy if exists delta_profile_admin_write on public.profiles;
create policy delta_profile_admin_write on public.profiles for update to authenticated
using ((select public.delta_es_admin())) with check ((select public.delta_es_admin()));

alter table public.productos enable row level security;
drop policy if exists delta_productos_ver on public.productos;
create policy delta_productos_ver on public.productos for select to anon,authenticated using (true);
drop policy if exists delta_productos_admin_insert on public.productos;
create policy delta_productos_admin_insert on public.productos for insert to authenticated
with check ((select public.delta_es_admin()));
drop policy if exists delta_productos_admin_update on public.productos;
create policy delta_productos_admin_update on public.productos for update to authenticated
using ((select public.delta_es_admin())) with check ((select public.delta_es_admin()));
drop policy if exists delta_productos_admin_delete on public.productos;
create policy delta_productos_admin_delete on public.productos for delete to authenticated
using ((select public.delta_es_admin()));

alter table public.pedidos enable row level security;
drop policy if exists delta_pedidos_leer on public.pedidos;
create policy delta_pedidos_leer on public.pedidos for select to authenticated
using (usuario_id = (select auth.uid()) or (select public.delta_es_admin()));
drop policy if exists delta_pedidos_admin_update on public.pedidos;
create policy delta_pedidos_admin_update on public.pedidos for update to authenticated
using ((select public.delta_es_admin())) with check ((select public.delta_es_admin()));

alter table public.pedido_items enable row level security;
drop policy if exists delta_items_leer on public.pedido_items;
create policy delta_items_leer on public.pedido_items for select to authenticated
using (exists(select 1 from public.pedidos p where p.id=pedido_id and (p.usuario_id=(select auth.uid()) or (select public.delta_es_admin()))));
alter table public.pedido_historial enable row level security;
drop policy if exists delta_historial_leer on public.pedido_historial;
create policy delta_historial_leer on public.pedido_historial for select to authenticated
using (exists(select 1 from public.pedidos p where p.id=pedido_id and (p.usuario_id=(select auth.uid()) or (select public.delta_es_admin()))));
alter table public.puntos_movimientos enable row level security;
drop policy if exists delta_puntos_leer on public.puntos_movimientos;
create policy delta_puntos_leer on public.puntos_movimientos for select to authenticated
using (usuario_id = (select auth.uid()) or (select public.delta_es_admin()));

-- Crear pedidos únicamente desde el servidor de Next.js, con la service role key.
-- El servidor obtiene user_id de auth.getUser(); no confía en el usuario del JSON.
create or replace function public.delta_crear_pedido(
 p_usuario_id uuid,
 p_nombre text,
 p_email text,
 p_telefono text,
 p_direccion text,
 p_items jsonb
) returns jsonb language plpgsql security definer set search_path = public as $$
declare
 v_pedido public.pedidos%rowtype;
 v_item jsonb;
 v_producto public.productos%rowtype;
 v_cantidad integer;
 v_total numeric(12,2) := 0;
 v_cuenta integer := 0;
 v_detalles jsonb := '[]'::jsonb;
begin
 if auth.role() <> 'service_role' then raise exception 'Acceso no autorizado'; end if;
 if length(trim(coalesce(p_nombre,''))) not between 2 and 120
    or length(trim(coalesce(p_telefono,''))) not between 7 and 30
    or length(trim(coalesce(p_direccion,''))) not between 5 and 250
 then raise exception 'Datos de entrega inválidos'; end if;
 if jsonb_typeof(p_items) <> 'array' or jsonb_array_length(p_items) not between 1 and 30 then
   raise exception 'El pedido debe incluir entre 1 y 30 productos';
 end if;
 -- Bloquear las filas de productos en orden fijo para evitar carreras y deadlocks.
 for v_item in select value from jsonb_array_elements(p_items) order by value->>'producto_id' loop
   if (v_item->>'cantidad') !~ '^[0-9]{1,3}$' then raise exception 'Cantidad inválida'; end if;
   v_cantidad := (v_item->>'cantidad')::integer;
   if v_cantidad not between 1 and 99 then raise exception 'Cantidad fuera de rango'; end if;
   select * into v_producto from public.productos where id=(v_item->>'producto_id')::uuid for update;
   if not found then raise exception 'Producto no encontrado'; end if;
   if v_producto.stock < v_cantidad then raise exception 'Inventario insuficiente para %',v_producto.name; end if;
   v_total:=v_total + v_producto.price*v_cantidad;
   v_cuenta:=v_cuenta+1;
   v_detalles:=v_detalles || jsonb_build_array(jsonb_build_object('producto_id',v_producto.id,'nombre',v_producto.name,'precio',v_producto.price,'cantidad',v_cantidad,'subtotal',v_producto.price*v_cantidad));
   update public.productos set stock=stock-v_cantidad where id=v_producto.id;
 end loop;
 insert into public.pedidos (codigo, usuario_id, cliente_nombre,cliente_email,cliente_telefono,direccion,total,estado)
 values ('DEL-'||upper(substr(replace(gen_random_uuid()::text,'-',''),1,12)),p_usuario_id,trim(p_nombre),nullif(trim(p_email),''),trim(p_telefono),trim(p_direccion),v_total,'nuevo')
 returning * into v_pedido;
 for v_item in select value from jsonb_array_elements(v_detalles) loop
   insert into public.pedido_items(pedido_id,producto_id,nombre,precio,cantidad,subtotal)
   values(v_pedido.id,(v_item->>'producto_id')::uuid,v_item->>'nombre',(v_item->>'precio')::numeric,(v_item->>'cantidad')::int,(v_item->>'subtotal')::numeric);
 end loop;
 insert into public.pedido_historial(pedido_id,estado,nota) values(v_pedido.id,'nuevo','Pedido registrado');
 return jsonb_build_object('id',v_pedido.id,'codigo',v_pedido.codigo,'total',v_total,'estado','nuevo','cliente_nombre',v_pedido.cliente_nombre,'direccion',v_pedido.direccion,'items',v_detalles);
end $$;
revoke all on function public.delta_crear_pedido(uuid,text,text,text,text,jsonb) from public,anon,authenticated;
grant execute on function public.delta_crear_pedido(uuid,text,text,text,text,jsonb) to service_role;

-- Cambio de estado y puntos en una misma transacción; ninguna recompensa por pedido nuevo.
create or replace function public.delta_cambiar_estado(
 p_pedido_id uuid,
 p_estado text,
 p_nota text default null
) returns jsonb language plpgsql security definer set search_path = public as $$
declare v_pedido public.pedidos%rowtype; v_puntos int;
begin
 if auth.role() <> 'service_role' then raise exception 'Acceso no autorizado'; end if;
 if p_estado not in ('nuevo','pagado','entregado','cancelado') then raise exception 'Estado inválido'; end if;
 select * into v_pedido from public.pedidos where id=p_pedido_id for update;
 if not found then raise exception 'Pedido no encontrado'; end if;
 if v_pedido.estado='cancelado' then raise exception 'Un pedido cancelado no se puede reabrir'; end if;
 if not ((v_pedido.estado='nuevo' and p_estado in ('pagado','cancelado')) or
         (v_pedido.estado='pagado' and p_estado in ('entregado','cancelado')) or
         v_pedido.estado=p_estado) then
   raise exception 'Transición de estado no permitida';
 end if;
 if v_pedido.estado=p_estado then
   return jsonb_build_object('id',v_pedido.id,'codigo',v_pedido.codigo,'estado',v_pedido.estado);
 end if;
 update public.pedidos set estado=p_estado where id=p_pedido_id;
 insert into public.pedido_historial(pedido_id,estado,nota) values(p_pedido_id,p_estado,left(coalesce(p_nota,''),500));
 -- 1 punto por cada COP 10.000 confirmados, solo para el cliente que había iniciado sesión al comprar.
 v_puntos:=floor(v_pedido.total/10000)::integer;
 if v_pedido.usuario_id is not null and v_puntos>0 then
   if p_estado='pagado' then
     insert into public.puntos_movimientos(usuario_id,pedido_id,tipo,puntos,descripcion)
     values(v_pedido.usuario_id,v_pedido.id,'GANADOS',v_puntos,'Puntos por pedido '||v_pedido.codigo)
     on conflict(pedido_id,tipo) do nothing;
   elsif p_estado='cancelado' and v_pedido.estado='pagado' then
     insert into public.puntos_movimientos(usuario_id,pedido_id,tipo,puntos,descripcion)
     select v_pedido.usuario_id,v_pedido.id,'REVERSADOS',-v_puntos,'Reversión por cancelación '||v_pedido.codigo
     where exists(select 1 from public.puntos_movimientos where pedido_id=v_pedido.id and tipo='GANADOS')
     on conflict(pedido_id,tipo) do nothing;
   end if;
 end if;
 if p_estado='cancelado' then
   update public.productos pr set stock=pr.stock + i.cantidad
   from public.pedido_items i where i.pedido_id=v_pedido.id and i.producto_id=pr.id;
 end if;
 return jsonb_build_object('id',v_pedido.id,'codigo',v_pedido.codigo,'estado',p_estado);
end $$;
revoke all on function public.delta_cambiar_estado(uuid,text,text) from public,anon,authenticated;
grant execute on function public.delta_cambiar_estado(uuid,text,text) to service_role;

-- Por seguridad, no abrir un pedido desde la consola de usuario con INSERT directo.
-- Para asignar administrador: cambiar el role desde SQL Editor, nunca desde el frontend:
-- update public.profiles set role='ADMIN' where id=(select id from auth.users where email='TU_CORREO');
-- Nota: si la BD ya tenía funciones legacy crear_pedido / cambiar_estado_pedido,
-- auditar sus permisos EXECUTE y retirarlos de anon/authenticated antes de producción.
