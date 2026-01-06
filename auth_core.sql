--
-- PostgreSQL database dump
--

\restrict 3NMsM6KdhUmobOgAarDbXmGppBTbsL3lWkcuqqPMb5RXNwEb0SNymtGSpfPYZHN

-- Dumped from database version 16.11 (Ubuntu 16.11-0ubuntu0.24.04.1)
-- Dumped by pg_dump version 16.11 (Ubuntu 16.11-0ubuntu0.24.04.1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: admin_unlock_user(text, text); Type: FUNCTION; Schema: public; Owner: prian
--

CREATE FUNCTION public.admin_unlock_user(p_admin_username text, p_target_username text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    -- Must be admin
    IF NOT is_admin(p_admin_username) THEN
        RAISE EXCEPTION 'Access denied: admin privileges required';
    END IF;

    -- Admin cannot unlock themselves
    IF p_admin_username = p_target_username THEN
        RAISE EXCEPTION 'Admins cannot unlock themselves';
    END IF;

    -- Unlock target user
    UPDATE users
    SET failed_login_attempts = 0,
        locked_at = NULL,
        updated_by = p_admin_username,
        updated_at = CURRENT_TIMESTAMP
    WHERE username = p_target_username;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'Target user not found';
    END IF;
END;
$$;


ALTER FUNCTION public.admin_unlock_user(p_admin_username text, p_target_username text) OWNER TO prian;

--
-- Name: is_admin(text); Type: FUNCTION; Schema: public; Owner: prian
--

CREATE FUNCTION public.is_admin(p_username text) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM users u
        JOIN user_roles ur ON u.user_id = ur.user_id
        JOIN roles r ON ur.role_id = r.role_id
        WHERE u.username = p_username
          AND r.role_name = 'ADMIN'
          AND u.is_active = TRUE
    );
END;
$$;


ALTER FUNCTION public.is_admin(p_username text) OWNER TO prian;

--
-- Name: is_secadmin(text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.is_secadmin(p_username text) RETURNS boolean
    LANGUAGE plpgsql
    AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1
        FROM users u
        JOIN user_roles ur ON u.user_id = ur.user_id
        JOIN roles r ON ur.role_id = r.role_id
        WHERE u.username = p_username
          AND r.role_name = 'SECADMIN'
          AND u.is_active = TRUE
    );
END;
$$;


ALTER FUNCTION public.is_secadmin(p_username text) OWNER TO postgres;

--
-- Name: login_user(text, text); Type: FUNCTION; Schema: public; Owner: prian
--

CREATE FUNCTION public.login_user(p_username text, p_password text) RETURNS TABLE(user_id integer, username character varying)
    LANGUAGE plpgsql
    AS $$
DECLARE
    v_user_id INT;
    v_username VARCHAR;
BEGIN
    -- Step 1: fetch user (only if active and not locked)
    SELECT u.user_id, u.username
    INTO v_user_id, v_username
    FROM users u
    WHERE u.username = p_username
      AND u.is_active = TRUE
      AND u.locked_at IS NULL;

    -- User not found or already locked
    IF NOT FOUND THEN
        RETURN;
    END IF;

    -- Step 2: check password
    IF NOT EXISTS (
        SELECT 1
        FROM users u
        WHERE u.user_id = v_user_id
          AND u.password_hash = crypt(p_password, u.password_hash)
    ) THEN
        -- Failed attempt → increment counter and maybe lock
        UPDATE users
        SET failed_login_attempts = failed_login_attempts + 1,
            locked_at = CASE
                WHEN failed_login_attempts + 1 >= 10
                THEN CURRENT_TIMESTAMP
                ELSE locked_at
            END
        WHERE users.user_id = v_user_id;

        RETURN;
    END IF;

    -- Step 3: successful login → reset counters
    UPDATE users
    SET failed_login_attempts = 0,
        locked_at = NULL,
        last_login = CURRENT_TIMESTAMP
    WHERE users.user_id = v_user_id;

    -- Step 4: return user
    user_id := v_user_id;
    username := v_username;
    RETURN NEXT;
END;
$$;


ALTER FUNCTION public.login_user(p_username text, p_password text) OWNER TO prian;

--
-- Name: secadmin_create_user(text, text, text, text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.secadmin_create_user(p_actor text, p_username text, p_password text, p_first_name text, p_last_name text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT is_secadmin(p_actor) THEN
        RAISE EXCEPTION 'SECADMIN required';
    END IF;

    INSERT INTO users (
        username, first_name, last_name,
        password_hash, created_by
    )
    VALUES (
        p_username,
        p_first_name,
        p_last_name,
        crypt(p_password, gen_salt('bf')),
        p_actor
    );
END;
$$;


ALTER FUNCTION public.secadmin_create_user(p_actor text, p_username text, p_password text, p_first_name text, p_last_name text) OWNER TO postgres;

--
-- Name: secadmin_reset_password(text, text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.secadmin_reset_password(p_actor text, p_target text, p_new_password text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT is_secadmin(p_actor) THEN
        RAISE EXCEPTION 'SECADMIN required';
    END IF;

    UPDATE users
    SET password_hash = crypt(p_new_password, gen_salt('bf')),
        failed_login_attempts = 0,
        locked_at = NULL,
        updated_by = p_actor,
        updated_at = CURRENT_TIMESTAMP
    WHERE username = p_target;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'User not found';
    END IF;
END;
$$;


ALTER FUNCTION public.secadmin_reset_password(p_actor text, p_target text, p_new_password text) OWNER TO postgres;

--
-- Name: secadmin_set_user_status(text, text, boolean); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.secadmin_set_user_status(p_actor text, p_target text, p_enable boolean) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT is_secadmin(p_actor) THEN
        RAISE EXCEPTION 'SECADMIN required';
    END IF;

    UPDATE users
    SET is_active = p_enable,
        disabled_at = CASE WHEN p_enable THEN NULL ELSE CURRENT_TIMESTAMP END,
        disabled_by = p_actor
    WHERE username = p_target;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'User not found';
    END IF;
END;
$$;


ALTER FUNCTION public.secadmin_set_user_status(p_actor text, p_target text, p_enable boolean) OWNER TO postgres;

--
-- Name: secadmin_unlock_user(text, text); Type: FUNCTION; Schema: public; Owner: postgres
--

CREATE FUNCTION public.secadmin_unlock_user(p_actor text, p_target text) RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF NOT is_secadmin(p_actor) THEN
        RAISE EXCEPTION 'SECADMIN required';
    END IF;

    UPDATE users
    SET failed_login_attempts = 0,
        locked_at = NULL,
        updated_by = p_actor,
        updated_at = CURRENT_TIMESTAMP
    WHERE username = p_target;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'User not found';
    END IF;
END;
$$;


ALTER FUNCTION public.secadmin_unlock_user(p_actor text, p_target text) OWNER TO postgres;

--
-- Name: users_audit(); Type: FUNCTION; Schema: public; Owner: prian
--

CREATE FUNCTION public.users_audit() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.created_by IS NULL THEN
            NEW.created_by := current_user;
        END IF;

        -- If someone inserts manually without created_at
        IF NEW.created_at IS NULL THEN
            NEW.created_at := CURRENT_TIMESTAMP;
        END IF;
    END IF;

    -- Always track updates
    NEW.updated_by := current_user;
    NEW.updated_at := CURRENT_TIMESTAMP;

    RETURN NEW;
END;
$$;


ALTER FUNCTION public.users_audit() OWNER TO prian;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: users; Type: TABLE; Schema: public; Owner: prian
--

CREATE TABLE public.users (
    user_id integer NOT NULL,
    first_name character varying(100),
    last_name character varying(100),
    username character varying(100),
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    created_by text DEFAULT CURRENT_USER,
    updated_by text,
    updated_at timestamp without time zone,
    is_active boolean DEFAULT true,
    disabled_at timestamp without time zone,
    disabled_by text,
    password_hash text,
    last_login timestamp without time zone,
    failed_login_attempts integer DEFAULT 0,
    locked_at timestamp without time zone,
    CONSTRAINT chk_failed_attempts_non_negative CHECK ((failed_login_attempts >= 0)),
    CONSTRAINT chk_user_active CHECK ((((is_active = true) AND (disabled_at IS NULL)) OR ((is_active = false) AND (disabled_at IS NOT NULL))))
);


ALTER TABLE public.users OWNER TO prian;

--
-- Name: active_users; Type: VIEW; Schema: public; Owner: prian
--

CREATE VIEW public.active_users AS
 SELECT user_id,
    first_name,
    last_name,
    username,
    created_at,
    created_by,
    updated_by,
    updated_at,
    is_active,
    disabled_at,
    disabled_by
   FROM public.users
  WHERE (is_active = true);


ALTER VIEW public.active_users OWNER TO prian;

--
-- Name: permissions; Type: TABLE; Schema: public; Owner: prian
--

CREATE TABLE public.permissions (
    permission_id integer NOT NULL,
    permission_name character varying(100) NOT NULL
);


ALTER TABLE public.permissions OWNER TO prian;

--
-- Name: permissions_permission_id_seq; Type: SEQUENCE; Schema: public; Owner: prian
--

CREATE SEQUENCE public.permissions_permission_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.permissions_permission_id_seq OWNER TO prian;

--
-- Name: permissions_permission_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: prian
--

ALTER SEQUENCE public.permissions_permission_id_seq OWNED BY public.permissions.permission_id;


--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: prian
--

CREATE TABLE public.role_permissions (
    role_id integer NOT NULL,
    permission_id integer NOT NULL
);


ALTER TABLE public.role_permissions OWNER TO prian;

--
-- Name: roles; Type: TABLE; Schema: public; Owner: prian
--

CREATE TABLE public.roles (
    role_id integer NOT NULL,
    role_name character varying(50) NOT NULL,
    description text,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


ALTER TABLE public.roles OWNER TO prian;

--
-- Name: roles_role_id_seq; Type: SEQUENCE; Schema: public; Owner: prian
--

CREATE SEQUENCE public.roles_role_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.roles_role_id_seq OWNER TO prian;

--
-- Name: roles_role_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: prian
--

ALTER SEQUENCE public.roles_role_id_seq OWNED BY public.roles.role_id;


--
-- Name: user_roles; Type: TABLE; Schema: public; Owner: prian
--

CREATE TABLE public.user_roles (
    user_id integer NOT NULL,
    role_id integer NOT NULL,
    assigned_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP,
    assigned_by text DEFAULT CURRENT_USER
);


ALTER TABLE public.user_roles OWNER TO prian;

--
-- Name: users_user_id_seq; Type: SEQUENCE; Schema: public; Owner: prian
--

CREATE SEQUENCE public.users_user_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.users_user_id_seq OWNER TO prian;

--
-- Name: users_user_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: prian
--

ALTER SEQUENCE public.users_user_id_seq OWNED BY public.users.user_id;


--
-- Name: permissions permission_id; Type: DEFAULT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.permissions ALTER COLUMN permission_id SET DEFAULT nextval('public.permissions_permission_id_seq'::regclass);


--
-- Name: roles role_id; Type: DEFAULT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.roles ALTER COLUMN role_id SET DEFAULT nextval('public.roles_role_id_seq'::regclass);


--
-- Name: users user_id; Type: DEFAULT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.users ALTER COLUMN user_id SET DEFAULT nextval('public.users_user_id_seq'::regclass);


--
-- Data for Name: permissions; Type: TABLE DATA; Schema: public; Owner: prian
--

COPY public.permissions (permission_id, permission_name) FROM stdin;
1	CREATE_USER
2	DISABLE_USER
3	VIEW_REPORTS
4	EDIT_INVENTORY
7	ENABLE_USER
8	UNLOCK_USER
9	RESET_PASSWORD
10	ASSIGN_ROLE
11	VIEW_ALL_DATA
\.


--
-- Data for Name: role_permissions; Type: TABLE DATA; Schema: public; Owner: prian
--

COPY public.role_permissions (role_id, permission_id) FROM stdin;
1	1
1	2
1	3
1	4
3	3
5	1
5	2
5	3
5	4
5	7
5	8
5	9
5	10
5	11
\.


--
-- Data for Name: roles; Type: TABLE DATA; Schema: public; Owner: prian
--

COPY public.roles (role_id, role_name, description, created_at) FROM stdin;
1	ADMIN	System administrator	2026-01-06 09:29:10.96037
2	MANAGER	Management level access	2026-01-06 09:29:10.96037
3	USER	Standard application user	2026-01-06 09:29:10.96037
4	READ_ONLY	View-only access	2026-01-06 09:29:10.96037
5	SECADMIN	Security administrator – full system access	2026-01-06 09:56:42.241484
\.


--
-- Data for Name: user_roles; Type: TABLE DATA; Schema: public; Owner: prian
--

COPY public.user_roles (user_id, role_id, assigned_at, assigned_by) FROM stdin;
6	3	2026-01-06 09:31:17.939761	prian
1	1	2026-01-06 09:31:22.689799	prian
6	4	2026-01-06 09:33:09.805844	prian
1	5	2026-01-06 09:56:57.779735	postgres
\.


--
-- Data for Name: users; Type: TABLE DATA; Schema: public; Owner: prian
--

COPY public.users (user_id, first_name, last_name, username, created_at, created_by, updated_by, updated_at, is_active, disabled_at, disabled_by, password_hash, last_login, failed_login_attempts, locked_at) FROM stdin;
2	Test	User	TESTUSER	2026-01-06 09:10:15.028399	prian	\N	\N	t	\N	\N	\N	\N	0	\N
3	Kyle Adrian	Pillay	PILLAYKA	2026-01-06 09:11:13.750425	prian	\N	\N	t	\N	\N	\N	\N	0	\N
4	Admin	SU	ADMIN	2026-01-06 09:12:21.185067	prian	\N	\N	t	\N	\N	\N	\N	0	\N
7	Mike	Brown	BROWNM	2026-01-06 09:17:17.259332	prian	prian	2026-01-06 09:19:27.733146	t	\N	\N	\N	\N	0	\N
1	Prian	Gounden	GOUNDENP	2026-01-06 09:07:55.744187	prian	prian	2026-01-06 09:44:32.118258	t	\N	\N	$2a$06$paCIv0aoelhweoYbcBbm/esWN1ANy.tZH1wQJcIDCx9rF7a/EMLh6	2026-01-06 09:43:32.624019	0	\N
6	Jane	Smith	JSMITH	2026-01-06 09:16:10.659084	prian	prian	2026-01-06 09:49:51.979074	t	\N	\N	$2a$06$mltMlihYUmtfa10c.oCQD.ZhAx7aISDI2PN8Z.CAjwx.1U3qoCElS	\N	0	\N
8	New	User	NEWUSER	2026-01-06 09:57:55.994841	GOUNDENP	postgres	2026-01-06 09:58:27.244969	t	\N	GOUNDENP	$2a$06$1Gy24ViKdXKphA.J9BNhpOCH0aBxgTjArT9.2q5pMeBDJGADT8L7G	\N	0	\N
\.


--
-- Name: permissions_permission_id_seq; Type: SEQUENCE SET; Schema: public; Owner: prian
--

SELECT pg_catalog.setval('public.permissions_permission_id_seq', 11, true);


--
-- Name: roles_role_id_seq; Type: SEQUENCE SET; Schema: public; Owner: prian
--

SELECT pg_catalog.setval('public.roles_role_id_seq', 5, true);


--
-- Name: users_user_id_seq; Type: SEQUENCE SET; Schema: public; Owner: prian
--

SELECT pg_catalog.setval('public.users_user_id_seq', 8, true);


--
-- Name: permissions permissions_permission_name_key; Type: CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_permission_name_key UNIQUE (permission_name);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (permission_id);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (role_id);


--
-- Name: roles roles_role_name_key; Type: CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_role_name_key UNIQUE (role_name);


--
-- Name: user_roles user_roles_pkey; Type: CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_pkey PRIMARY KEY (user_id, role_id);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (user_id);


--
-- Name: users users_username_key; Type: CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_username_key UNIQUE (username);


--
-- Name: users trg_users_audit; Type: TRIGGER; Schema: public; Owner: prian
--

CREATE TRIGGER trg_users_audit BEFORE INSERT OR UPDATE ON public.users FOR EACH ROW EXECUTE FUNCTION public.users_audit();


--
-- Name: role_permissions role_permissions_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(permission_id);


--
-- Name: role_permissions role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(role_id);


--
-- Name: user_roles user_roles_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(role_id) ON DELETE CASCADE;


--
-- Name: user_roles user_roles_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: prian
--

ALTER TABLE ONLY public.user_roles
    ADD CONSTRAINT user_roles_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(user_id) ON DELETE CASCADE;


--
-- PostgreSQL database dump complete
--

\unrestrict 3NMsM6KdhUmobOgAarDbXmGppBTbsL3lWkcuqqPMb5RXNwEb0SNymtGSpfPYZHN

