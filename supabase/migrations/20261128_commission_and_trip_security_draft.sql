-- مشواري برج العرب: مسودة ترحيل محاسبة وتأمين إكمال الرحلات
-- راجعها قبل تشغيلها على Supabase. لا تحذف بيانات ولا تغير سياسات RLS الحالية.

begin;

-- دفتر حسابات منفصل: charge = مديونية، payment = سداد/تسوية.
create table if not exists public.trip_commission_ledger (
  id bigint generated always as identity primary key,
  trip_id uuid not null references public.trips(id) on delete restrict,
  account_user_id uuid not null references auth.users(id) on delete restrict,
  side text not null check (side in ('passenger','driver')),
  entry_type text not null check (entry_type in ('charge','payment')),
  amount numeric(10,2) not null check (amount > 0),
  created_at timestamptz not null default now(),
  created_by uuid references auth.users(id),
  note text
);
-- يسمح بتكرار السداد؛ تكرار العمولة يمنع بواسطة partial unique index أدناه.
create unique index if not exists commission_charge_once
  on public.trip_commission_ledger(trip_id, side) where entry_type='charge';

alter table public.trip_commission_ledger enable row level security;

-- لا يسمح للمستخدمين بإضافة أو تعديل الدفتر مباشرة.
revoke all on public.trip_commission_ledger from anon, authenticated;
grant select on public.trip_commission_ledger to authenticated;

drop policy if exists commission_ledger_own_read on public.trip_commission_ledger;
create policy commission_ledger_own_read on public.trip_commission_ledger
for select to authenticated
using (account_user_id = auth.uid());

-- رصيد السائق: مجموع المديونيات (charge) ناقص السداد/التسوية.
create or replace function public.driver_commission_balance()
returns numeric
language sql stable security definer
set search_path = ''
as $
  select coalesce(sum(
    case when entry_type='charge' then amount
         when entry_type='payment' then -amount
         else 0 end
  ),0)::numeric
  from public.trip_commission_ledger
  where account_user_id=auth.uid() and side='driver';
$;
revoke all on function public.driver_commission_balance() from public, anon;
grant execute on function public.driver_commission_balance() to authenticated;

-- قبول طلب: سائق معتمد، لا تتجاوز مديونيته 10 جنيه، والطلب متاح.
create or replace function public.accept_trip(trip_uuid uuid)
returns void
language plpgsql security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_profile public.profiles%rowtype;
begin
  if v_user is null then raise exception 'Authentication required'; end if;
  select * into v_profile from public.profiles where id=v_user;
  if not found or v_profile.role <> 'driver' or v_profile.approved is not true then
    raise exception 'Driver is not approved';
  end if;
  if public.driver_commission_balance() >= 10 then
    raise exception 'Commission debt limit reached; settle your balance';
  end if;
  update public.trips
  set driver_id=v_user, status='accepted'
  where id=trip_uuid and status='pending' and driver_id is null;
  if not found then raise exception 'Trip is no longer available'; end if;
end;
$$;
revoke all on function public.accept_trip(uuid) from public, anon;
grant execute on function public.accept_trip(uuid) to authenticated;


-- بدء الرحلة: لا يسمح إلا للسائق المعيّن وبحالة accepted.
create or replace function public.start_trip(trip_uuid uuid)
returns void
language plpgsql security definer
set search_path = ''
as $
declare v_user uuid := auth.uid();
begin
  if v_user is null then raise exception 'Authentication required'; end if;
  update public.trips set status='started'
  where id=trip_uuid and driver_id=v_user and status='accepted';
  if not found then raise exception 'Trip cannot be started'; end if;
end;
$;
revoke all on function public.start_trip(uuid) from public, anon;
grant execute on function public.start_trip(uuid) to authenticated;

-- إكمال الرحلة وتسجيل العمولة بشكل ذري، مرة واحدة لكل طرف.
create or replace function public.complete_trip(trip_uuid uuid)
returns void
language plpgsql security definer
set search_path = ''
as $$
declare
  v_user uuid := auth.uid();
  v_trip public.trips%rowtype;
begin
  if v_user is null then raise exception 'Authentication required'; end if;
  select * into v_trip from public.trips where id=trip_uuid for update;
  if not found then raise exception 'Trip not found'; end if;
  if v_trip.driver_id is distinct from v_user then raise exception 'Not assigned to this driver'; end if;
  if v_trip.status <> 'started' then raise exception 'Trip must be started before completion'; end if;

  update public.trips set status='completed' where id=trip_uuid;

  insert into public.trip_commission_ledger(trip_id,account_user_id,side,entry_type,amount,created_by,note)
  values (trip_uuid,v_trip.passenger_id,'passenger','charge',1,v_user,'Passenger trip commission'),
         (trip_uuid,v_user,'driver','charge',1,v_user,'Driver trip commission')
  on conflict (trip_id,side) where entry_type='charge' do nothing;
end;
$$;
revoke all on function public.complete_trip(uuid) from public, anon;
grant execute on function public.complete_trip(uuid) to authenticated;

commit;

-- ملاحظة أمان: هذه الدوال لا تُغني عن مراجعة سياسات UPDATE الحالية على trips.
-- ينبغي منع تحديث status مباشرة من العميل وإتاحته عبر RPC فقط، بعد مراجعة أسماء السياسات الفعلية.
