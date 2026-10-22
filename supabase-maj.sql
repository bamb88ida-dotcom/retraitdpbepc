-- MISE A JOUR : à coller dans Supabase > SQL Editor > New query, puis Run (une seule fois)
alter table public.diplomes add column if not exists deco_date text;

alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check check (role in ('admin','agent','chef'));

create or replace function public.remettre(p_id bigint,p_date text,p_par text,p_pc text,p_c1 text,p_c2 text)
returns void language plpgsql security definer set search_path=public as $$
declare lg text; d record;
begin
  if not public.can_remit() then raise exception 'Vous n''êtes pas autorisé à remettre un diplôme.'; end if;
  select login into lg from profiles where id=auth.uid();
  select * into d from diplomes where id=p_id for update;
  if not found then raise exception 'Diplôme introuvable.'; end if;
  if d.r_date is not null or d.r_par is not null or d.r_pc is not null then raise exception 'Ce diplôme a déjà été retiré.'; end if;
  if d.deco_date is not null then raise exception 'Ce diplôme est retourné à la DECO.'; end if;
  update diplomes set r_date=p_date,r_par=p_par,r_pc=p_pc,r_c1=nullif(p_c1,''),r_c2=nullif(p_c2,''),r_agent=lg,r_at=now() where id=p_id;
  insert into journal(usr,action,detail) values(lg,'Remise',d.nom||' (session '||d.ses||', table '||d.tab||') — retiré par '||p_par||', pièce '||p_pc);
end $$;
grant execute on function public.remettre(bigint,text,text,text,text,text) to authenticated;

create or replace function public.admin_set_password(p_id uuid,p_pw text)
returns void language plpgsql security definer set search_path=public,extensions,auth as $$
declare lg text; cible text;
begin
  if not public.is_admin() then raise exception 'Non autorisé.'; end if;
  if length(p_pw)<6 then raise exception 'Mot de passe trop court (6 caractères minimum).'; end if;
  select login into cible from public.profiles where id=p_id;
  if cible is null then raise exception 'Compte introuvable.'; end if;
  update auth.users set encrypted_password=crypt(p_pw,gen_salt('bf',10)),updated_at=now() where id=p_id;
  select login into lg from public.profiles where id=auth.uid();
  insert into public.journal(usr,action,detail) values(lg,'Mot de passe réinitialisé',cible);
end $$;
revoke all on function public.admin_set_password(uuid,text) from public, anon;
grant execute on function public.admin_set_password(uuid,text) to authenticated;
