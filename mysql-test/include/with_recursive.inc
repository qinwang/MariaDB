SET @@max_recursive_iterations = 10000;
flush STATUS;

--echo # Mutual recursion unsupported; cycles must have one node only
--error ER_RECURSIVE_WITHOUT_ANCHORS
WITH RECURSIVE qn AS (SELECT * FROM qn2),
               qn2 AS (SELECT * FROM qn)
SELECT * FROM qn;

--echo # At least one anchor member, all anchors before all recursive

--error ER_RECURSIVE_WITHOUT_ANCHORS
WITH RECURSIVE qn AS
  (SELECT 1 FROM qn)
SELECT count(*) FROM qn;

WITH RECURSIVE qn AS
  (SELECT 1 UNION ALL SELECT 1 FROM qn UNION ALL SELECT 1)
SELECT count(*) FROM qn;

--error ER_RECURSIVE_WITHOUT_ANCHORS
WITH RECURSIVE qn AS
  (SELECT 1 FROM qn UNION ALL SELECT 1 FROM qn)
SELECT * FROM qn;

--echo # It's ok to have the RECURSIVE word without any recursive member

WITH RECURSIVE qn AS
  (SELECT 1 FROM dual UNION ALL
   SELECT 1 FROM dual)
SELECT * FROM qn;

--echo # UNION DISTINCT allowed

WITH RECURSIVE qn AS
  (SELECT 1 FROM dual UNION
   SELECT 1 FROM qn)
SELECT * FROM qn;

--echo # No aggregation on the QN
CREATE TABLE t1(b int);
INSERT INTO t1 VALUES(10),(20),(10);

WITH RECURSIVE qn AS
  (SELECT max(b) AS a FROM t1 UNION
   SELECT a FROM qn)
SELECT * FROM qn;

--error ER_NOT_STANDARD_COMPLIANT_RECURSIVE
WITH RECURSIVE qn AS
  (SELECT b AS a FROM t1 UNION
   SELECT max(a) FROM qn)
SELECT * FROM qn;

--echo # No window functions
WITH RECURSIVE qn AS
  (SELECT rank() over (ORDER BY b) AS a FROM t1 UNION
   SELECT a FROM qn)
SELECT * FROM qn;
--error ER_NOT_STANDARD_COMPLIANT_RECURSIVE
WITH RECURSIVE qn AS
  (SELECT b AS a FROM t1 UNION
   SELECT rank() over (ORDER BY a) FROM qn)
SELECT * FROM qn;
DROP TABLE t1;

--error ER_NOT_STANDARD_COMPLIANT_RECURSIVE
WITH RECURSIVE qn AS
  (SELECT 1 AS a FROM dual UNION ALL
   SELECT max(a) FROM qn)
SELECT * FROM qn;

WITH RECURSIVE qn AS
  (SELECT 1 AS a FROM dual GROUP BY a UNION ALL
   SELECT a+1 FROM qn WHERE a<3)
SELECT * FROM qn;

WITH RECURSIVE qn AS
  (SELECT 1 AS a FROM dual UNION ALL
   SELECT a FROM qn GROUP BY a)
SELECT count(*)FROM qn;

--echo # No subquery referencing a QN
--error ER_NOT_STANDARD_COMPLIANT_RECURSIVE
WITH RECURSIVE qn AS (
SELECT 1 FROM dual UNION ALL
SELECT 1 FROM dual WHERE 1 NOT in(SELECT * FROM qn))
SELECT * FROM qn;

--error ER_NOT_SUPPORTED_YET
WITH RECURSIVE qn AS (
SELECT 1 FROM dual UNION ALL
SELECT 1 FROM qn
ORDER BY (SELECT * FROM qn))
SELECT count(*) FROM qn;

WITH RECURSIVE qn AS (
SELECT 1 FROM dual UNION ALL
SELECT * FROM (SELECT * FROM qn) AS dt)
SELECT count(*) FROM qn;

--error ER_NOT_SUPPORTED_YET
WITH RECURSIVE qn AS (
SELECT 1 AS a FROM dual UNION ALL
SELECT 1 FROM qn
ORDER BY a)
SELECT count(*) FROM qn;
--echo # No matter if global, or attached to one recursive member.

WITH RECURSIVE qn AS (
SELECT 1 AS a FROM dual UNION ALL
(SELECT 1 FROM qn ORDER BY a))
SELECT count(*) FROM qn;

--echo # Allowed on non-recursive query block (though pointless)
WITH RECURSIVE qn AS (
(SELECT 1 AS a FROM dual ORDER BY a) UNION ALL
SELECT a+1 FROM qn WHERE a<3)
SELECT * FROM qn;

--error ER_NOT_SUPPORTED_YET
WITH RECURSIVE qn AS (
SELECT 1 AS a FROM dual UNION ALL
SELECT 1 FROM qn
LIMIT 10)
SELECT count(*) FROM qn;

WITH RECURSIVE qn AS (
SELECT 1 AS a FROM dual UNION ALL
(SELECT 1 FROM qn LIMIT 10))
SELECT count(*) FROM qn;

WITH RECURSIVE qn AS
(SELECT 1 UNION ALL SELECT DISTINCT 3 FROM qn)
SELECT count(*) FROM qn;

--error 4008
WITH RECURSIVE qn AS (SELECT 1 FROM dual UNION ALL
                      SELECT 1 FROM dual
                        WHERE 1 NOT in(SELECT * FROM qn))
SELECT * FROM qn;

--echo # Numbers from 123 to 130:

WITH RECURSIVE qn AS (SELECT 123 AS a UNION ALL SELECT 1+a FROM qn WHERE a<130) SELECT * FROM qn;

--echo # One-level recursive sequence of numbers
WITH RECURSIVE qn AS (SELECT 1 AS n, 2 AS un UNION ALL SELECT 1+n, un*5-6 FROM qn WHERE n<10) SELECT * FROM qn;

--echo # Fibonacci

WITH RECURSIVE qn AS (SELECT 1 AS n, 1 AS un, 1 AS unp1 UNION ALL SELECT 1+n, unp1, un+unp1 FROM qn WHERE n<10) SELECT * FROM qn;

--echo # Validate that cast(a_varchar as char) produces a varchar, not a
--echo # char.
CREATE TABLE t(c char(3), vc varchar(3), b binary(3), vb varbinary(3));
CREATE TABLE u
SELECT cast(c AS char(4)), cast(vc AS char(4)),
       cast(b AS binary(4)), cast(vb AS binary(4)),
       "abc" AS literal_c, cast("abc" AS char(4)),
       _binary "abc" AS literal_b, cast(_binary "abc" AS binary(4))
FROM t;
SHOW CREATE TABLE u;
DROP TABLE t,u;

--echo # if it used char the 'x' would fall off due to spaces.
WITH RECURSIVE qn AS (SELECT 1 AS n, cast('x' AS char(100)) AS un UNION ALL SELECT 1+n, concat(un,'x') FROM qn WHERE n<10) SELECT * FROM qn;

--echo # String now growing at the left

WITH RECURSIVE qn AS (SELECT cast("x" AS char(10)) AS a FROM dual
UNION ALL SELECT concat("x",a) FROM qn WHERE length(a)<10) SELECT *
FROM qn;

--echo # Forgot cast-as-char(10) in anchor => qn.a column has length 1
--echo # => concat() is cast as char(1) => truncation
--echo # => length is always 1 => infinite loop;

let $query=
WITH RECURSIVE qn AS (SELECT "x" AS a FROM dual
UNION ALL SELECT concat("x",a) FROM qn WHERE length(a)<10) SELECT count(*)
FROM qn;
eval $query;

--echo # Overflow integer type INT (max 4G)
--error ER_DATA_OUT_OF_RANGE
WITH RECURSIVE qn AS (SELECT 1 AS a FROM dual
UNION ALL SELECT a*2000 FROM qn WHERE a<10000000000000000000) SELECT count(*) FROM qn;

--echo # Use Decimal
WITH RECURSIVE qn AS (SELECT cast(1 AS decimal(30,0)) AS a FROM dual
UNION ALL SELECT a*2000 FROM qn WHERE a<10000000000000000000) SELECT * FROM qn;

#MDEV-16505
WITH RECURSIVE qn AS (SELECT 123 AS a UNION #ALL 
SELECT NULL FROM qn WHERE a IS NOT NULL) SELECT * FROM qn;

--echo # Mixing really unrelated types: the goal is to report a sensible
--echo # error and not crash.

--echo # The Point becomes a string which is an invalid integer, cast string to int -> result 0:

WITH RECURSIVE qn AS (
SELECT 1 AS a,1
UNION ALL
SELECT a+1,ST_PointFromText('POINT(10 10)') FROM qn WHERE a<2)
SELECT * FROM qn;

--echo # POINT in anchor => BLOB in tmp table => not MEMORY engine => Innodb
--error ER_CANT_CREATE_GEOMETRY_OBJECT
WITH RECURSIVE qn AS (
SELECT 1 AS a,ST_PointFromText('POINT(10 10)')
UNION ALL
SELECT a+1,1 FROM qn WHERE a<2)
SELECT * FROM qn;

--echo # Same number of columns in anchor and recursive members
--error ER_WRONG_NUMBER_OF_COLUMNS_IN_SELECT
WITH RECURSIVE qn AS
(
SELECT 1
UNION ALL
SELECT 3, 0 FROM qn
)
SELECT * FROM qn;

--echo # Mismatch in column name and column count; problem specific of
--echo # recursive CTE which creates tmp table earlier in preparation.
--error ER_WITH_COL_WRONG_LIST
WITH RECURSIVE q (b) AS (SELECT 1, 1 UNION ALL SELECT 1, 1 FROM q)
SELECT b FROM q;

--echo # Cannot have two recursive refs in FROM:

--error 4008
WITH RECURSIVE qn AS (
SELECT 123 AS a UNION ALL
SELECT 1+qn.a FROM qn, qn AS qn1 WHERE qn1.a<130)
SELECT * FROM qn;

--echo # Prove that a materialized QN is shared among all references:

flush STATUS;
WITH RECURSIVE qn AS (
SELECT 123 AS a UNION ALL
SELECT 1+a FROM qn WHERE a<125)
SELECT * FROM qn;
SHOW STATUS LIKE "handler_write";
flush STATUS;
WITH RECURSIVE qn AS (
SELECT 123 AS a UNION ALL
SELECT 1+a FROM qn WHERE a<125)
SELECT * FROM qn, qn AS qn1;
SHOW STATUS LIKE "handler_write";
SHOW STATUS LIKE 'Created_tmp%table%';

--echo # Also works if references are nested inside other query names:
flush STATUS;
WITH RECURSIVE inner_ AS (
SELECT 123 AS a UNION ALL
SELECT 1+a FROM inner_ WHERE a<125),
outer_ AS (SELECT * FROM inner_ LIMIT 10)
SELECT * FROM outer_, outer_ AS outer1;
SHOW STATUS LIKE "handler_write";

flush STATUS;
WITH RECURSIVE inner_ AS (
SELECT 123 AS a UNION ALL
SELECT 1+a FROM inner_ WHERE a<125),
outer_ AS
(SELECT inner_.a, inner1.a AS a1
FROM inner_, inner_ AS inner1 LIMIT 10)
SELECT * FROM outer_;
SHOW STATUS LIKE "handler_write";

--echo # Even if the two query names are recursive:
flush STATUS;
WITH RECURSIVE inner_ AS (
SELECT 123 AS a UNION ALL
SELECT 1+a FROM inner_ WHERE a<125),
outer_ AS
(SELECT a FROM inner_ UNION ALL
SELECT a*2 FROM outer_ WHERE a<1000)
SELECT a FROM outer_;
SHOW STATUS LIKE "handler_write";

--echo # Optimizer must be allowed to put the recursive reference first

CREATE TABLE t1(a int);
INSERT INTO t1 VALUES(1),(2);

--error ER_NOT_STANDARD_COMPLIANT_RECURSIVE
WITH RECURSIVE qn AS
(
SELECT 1 FROM t1
UNION ALL
SELECT 1 FROM t1 LEFT JOIN qn ON 1
)
SELECT * FROM qn;

--echo # Empty anchor

WITH RECURSIVE qn AS
(
SELECT a FROM t1 WHERE 0
UNION ALL
SELECT a+1 FROM qn
)
SELECT * FROM qn;

WITH RECURSIVE qn AS
(
SELECT a FROM t1 WHERE a>10
UNION ALL
SELECT a+1 FROM qn
)
SELECT * FROM qn;

--echo # UNION DISTINCT in anchor parts 
INSERT INTO t1 VALUES(1),(2);
SET @c=0, @d=0;
--error ER_NOT_SUPPORTED_YET
WITH RECURSIVE qn AS
(
SELECT 1,0 AS col FROM t1
UNION DISTINCT
SELECT 1,0 FROM t1
UNION ALL
SELECT 3, 0*(@c:=@c+1) FROM qn WHERE @c<1
UNION ALL
SELECT 3, 0*(@d:=@d+1) FROM qn WHERE @d<1
)
SELECT * FROM qn;

--echo # UNION DISTINCT affecting recursive member, followed by UNION ALL
INSERT INTO t1 VALUES(1),(2);

SET @c=0, @d=0;
--error ER_NOT_SUPPORTED_YET
WITH RECURSIVE qn AS
(
SELECT 1,0 AS col FROM t1
UNION DISTINCT
SELECT 3, 0*(@c:=@c+1) FROM qn WHERE @c<1
UNION ALL
SELECT 3, 0*(@d:=@d+1) FROM qn WHERE @d<1
)
SELECT * FROM qn;

--echo # create select
CREATE TABLE t2
WITH RECURSIVE qn AS (
SELECT 123 AS a UNION ALL SELECT 1+a FROM qn WHERE a<130)
SELECT * FROM qn;
SELECT * FROM t2;
DROP TABLE t2;

--echo # insert select
DELETE FROM t1;
INSERT INTO t1
WITH RECURSIVE qn AS (
SELECT 123 AS a UNION ALL SELECT 1+a FROM qn WHERE a<130)
SELECT * FROM qn;
SELECT * FROM t1;

--echo # Using insertion target inside recursive query
DELETE FROM t1;
INSERT INTO t1 VALUES(1),(2);
INSERT INTO t1
WITH RECURSIVE qn AS (
SELECT 123 AS a UNION ALL SELECT 1+qn.a FROM qn, t1 WHERE qn.a<125)
SELECT * FROM qn;
SELECT * FROM t1;

DROP TABLE t1;

--echo # insert into tmp table (a likely use case)

CREATE TEMPORARY TABLE t1(a int);
INSERT INTO t1
WITH RECURSIVE qn AS (
SELECT 123 AS a UNION ALL SELECT 1+a FROM qn WHERE a<130)
SELECT * FROM qn;
SELECT * FROM t1;
DROP TABLE t1;

--echo # create view
CREATE VIEW v1 AS
WITH RECURSIVE qn AS (
SELECT 123 AS a UNION ALL SELECT 1+a FROM qn WHERE a<130)
SELECT * FROM qn;
SELECT * FROM v1;
DROP VIEW v1;

--echo # Recursive QN can be constant (0-row or 1-row) for the
--echo # optimizer if its members have impossible conditions:

#EXPLAIN WITH RECURSIVE qn AS (SELECT 1 AS n WHERE 0 UNION ALL SELECT n+1 FROM qn WHERE 0) SELECT * FROM qn;
#WITH RECURSIVE qn AS (SELECT 1 AS n WHERE 0 UNION ALL SELECT n+1 FROM qn WHERE 0) SELECT * FROM qn;

#EXPLAIN WITH RECURSIVE qn AS (SELECT 1 AS n WHERE 1 UNION ALL SELECT n+1 FROM qn WHERE 0) SELECT * FROM qn;
#WITH RECURSIVE qn AS (SELECT 1 AS n WHERE 0 UNION ALL SELECT n+1 FROM qn WHERE 0) SELECT * FROM qn;

--echo # Recursive refs should never use indexes to read:
--echo # first, optimization of top query creates a key on q.b;
--echo # then optimization of scalar subquery, when it optimizes the
--echo # recursive member, must be prevented from re-using this key
--echo # (it was a bug that it re-used it, as the index is covering
--echo # and adjust_access_methods() has a heuristic which converts a
--echo # table scan to index scan, so it wrongly used an index scan).
let $query=
WITH RECURSIVE q (b) AS
 (SELECT 1 UNION ALL SELECT 1+b FROM q WHERE b<10)
 SELECT (SELECT q1.b FROM q AS q2 WHERE q2.b=3) FROM q AS q1 WHERE q1.b=3;
eval EXPLAIN $query;
eval $query;

--echo # This is from my blog so I can use it here.
--echo # Tests depth-first etc

CREATE TABLE employees (
ID INT PRIMARY KEY,
NAME VARCHAR(100),
MANAGER_ID INT,
INDEX (MANAGER_ID),
FOREIGN KEY (MANAGER_ID) REFERENCES employees(ID)
);
INSERT INTO employees VALUES
(333, "Yasmina", NULL),
(198, "John", 333),
(692, "Tarek", 333),
(29, "Pedro", 198),
(4610, "Sarah", 29),
(72, "Pierre", 29),
(123, "Adil", 692);
ANALYZE TABLE employees;

--echo # Depth-first.

--echo # Also test column names, and their reference in the recursive member.
WITH RECURSIVE employees_extended(ID, NAME, PATH)
AS
(
  SELECT ID, NAME, CAST(ID AS CHAR(200))
  FROM employees
  WHERE MANAGER_ID IS NULL
UNION ALL
  SELECT S.ID, S.NAME, CONCAT(M.PATH, ",", S.ID)
  FROM employees_extended M STRAIGHT_JOIN employees S ON M.ID=S.MANAGER_ID
)
SELECT * FROM employees_extended ORDER BY PATH;

--echo # Breadth-first is likely what we get, if no ordering

WITH RECURSIVE employees_extended
AS
(
  SELECT ID, NAME, CAST(ID AS CHAR(200)) AS PATH
  FROM employees
  WHERE MANAGER_ID IS NULL
UNION ALL
  SELECT S.ID, S.NAME, CONCAT(M.PATH, ",", S.ID)
  FROM employees_extended M STRAIGHT_JOIN employees S ON M.ID=S.MANAGER_ID
)
SELECT * FROM employees_extended;

--echo # But to be really sure we have breadth-first, we generate a
--echo # numeric column SEQ. And sort by NAME, to have repeatable
--echo # order of siblings (who have the same SEQ).

WITH RECURSIVE employees_extended
AS
(
  SELECT 0 AS SEQ, ID, NAME, CAST(ID AS CHAR(200)) AS PATH
  FROM employees
  WHERE MANAGER_ID IS NULL
UNION ALL
  SELECT M.SEQ+1, S.ID, S.NAME, CONCAT(M.PATH, ",", S.ID)
  FROM employees_extended M STRAIGHT_JOIN employees S ON M.ID=S.MANAGER_ID
)
SELECT * FROM employees_extended ORDER BY SEQ, NAME;

--echo # Or, use a user variable, then all rows have different number:

WITH RECURSIVE employees_extended
AS
(
  SELECT (@s:=0) AS SEQ, ID, NAME, CAST(ID AS CHAR(200)) AS PATH
  FROM employees
  WHERE MANAGER_ID IS NULL
UNION ALL
  SELECT (@s:=@s+1), S.ID, S.NAME, CONCAT(M.PATH, ",", S.ID)
  FROM employees_extended M STRAIGHT_JOIN employees S ON M.ID=S.MANAGER_ID
)
SELECT * FROM employees_extended ORDER BY SEQ;

--echo # Direct & indirect reports of John = having John in their PATH

WITH RECURSIVE employees_extended
AS
(
  SELECT ID, NAME, CAST(ID AS CHAR(200)) AS PATH
  FROM employees
  WHERE MANAGER_ID IS NULL
UNION ALL
  SELECT S.ID, S.NAME, CONCAT(M.PATH, ",", S.ID)
  FROM employees_extended M STRAIGHT_JOIN employees S ON M.ID=S.MANAGER_ID
)
SELECT * FROM employees_extended
WHERE FIND_IN_SET((SELECT ID FROM employees WHERE NAME='John'),
                  PATH);

--echo # Exclude John, he's not a report of himself;
--echo # bonus: use a QN to cache his ID.

WITH RECURSIVE employees_extended(ID, NAME, PATH)
AS
(
  SELECT ID, NAME, CAST(ID AS CHAR(200))
  FROM employees
  WHERE MANAGER_ID IS NULL
UNION ALL
  SELECT S.ID, S.NAME, CONCAT(M.PATH, ",", S.ID)
  FROM employees_extended M STRAIGHT_JOIN employees S ON M.ID=S.MANAGER_ID
),
JOHN_ID AS (SELECT ID FROM employees WHERE NAME='John')
SELECT e.* FROM employees_extended e, JOHN_ID
WHERE FIND_IN_SET(JOHN_ID.ID,
                  PATH)
      AND e.ID<>JOHN_ID.ID;

--echo # Similar, but faster: start dive at John (and include him again).
WITH RECURSIVE employees_extended
AS
(
  SELECT ID, NAME, CAST(ID AS CHAR(200)) AS PATH
  FROM employees
  WHERE NAME='John'
UNION ALL
  SELECT S.ID, S.NAME, CONCAT(M.PATH, ",", S.ID)
  FROM employees_extended M STRAIGHT_JOIN employees S ON M.ID=S.MANAGER_ID
)
SELECT * FROM employees_extended;

--echo # Get the management chain above Pierre:

WITH RECURSIVE employees_extended
AS
(
  SELECT ID, NAME, MANAGER_ID, CAST(ID AS CHAR(200)) AS PATH
  FROM employees
  WHERE NAME='Pierre'
UNION ALL
  SELECT S.ID, S.NAME, S.MANAGER_ID, CONCAT(M.PATH, ",", S.ID)
  FROM employees_extended M JOIN employees S ON M.MANAGER_ID=S.ID
)
SELECT * FROM employees_extended;

--echo # Get the management chain above Pierre, without PATH

WITH RECURSIVE employees_extended
AS
(
  SELECT ID, NAME, MANAGER_ID
  FROM employees
  WHERE NAME='Pierre'
UNION ALL
  SELECT S.ID, S.NAME, S.MANAGER_ID
  FROM employees_extended M JOIN employees S ON M.MANAGER_ID=S.ID
)
SELECT * FROM employees_extended;

--echo # Get the management chain above Pierre and Sarah, without PATH

WITH RECURSIVE employees_extended
AS
(
  SELECT ID, NAME, MANAGER_ID
  FROM employees
  WHERE NAME='Pierre' OR NAME='Sarah'
UNION ALL
  SELECT S.ID, S.NAME, S.MANAGER_ID
  FROM employees_extended M JOIN employees S ON M.MANAGER_ID=S.ID
)
SELECT * FROM employees_extended;

--echo # Do it without duplicates

WITH RECURSIVE employees_extended
AS
(
  SELECT ID, NAME, MANAGER_ID
  FROM employees
  WHERE NAME='Pierre' OR NAME='Sarah'
UNION
  SELECT S.ID, S.NAME, S.MANAGER_ID
  FROM employees_extended M JOIN employees S ON M.MANAGER_ID=S.ID
)
SELECT * FROM employees_extended;

--echo # Cycles. Introduce an oddity:

--echo # Sarah is indirect report of John and is his manager.
UPDATE employees SET MANAGER_ID=4610 WHERE NAME="John";

--echo # Add cycle detection: the row closing a cycle is marked with
--echo # IS_CYCLE=1, which stops the iterations. The outer SELECT
--echo # could then want to see only that row, or only previous ones.
WITH RECURSIVE employees_extended(ID, NAME, PATH, IS_CYCLE)
AS
(
  SELECT ID, NAME, CAST(ID AS CHAR(200)), 0
  FROM employees
  WHERE NAME='John'
UNION ALL
  SELECT S.ID, S.NAME, CONCAT(M.PATH, ",", S.ID), FIND_IN_SET(S.ID, M.PATH)
  FROM employees_extended M STRAIGHT_JOIN employees S ON M.ID=S.MANAGER_ID
  WHERE M.IS_CYCLE=0
)
SELECT * FROM employees_extended;

DROP TABLE employees;

--echo # Two recursive members.

CREATE TABLE t1 (id int, name char(10), leftpar int, rightpar int);
INSERT INTO t1 VALUES
(1, "A", 2, 3),
  (2, "LA", 4, 5),
     (4, "LLA", 6, 7),
        (6, "LLLA", NULL, NULL),
        (7, "RLLA", NULL, NULL),
     (5, "RLA", 8, 9),
        (8, "LRLA", NULL, NULL),
        (9, "RRLA", NULL, NULL),
  (3, "RA", 10, 11),
     (10, "LRA", 12, 13),
     (11, "RRA", 14, 15),
        (15, "RRRA", NULL, NULL),
(16, "B", 17, 18),
  (17, "LB", NULL, NULL),
  (18, "RB", NULL, NULL)
;

--echo # Shuffle rows to make sure the algorithm works
--echo # with any read order of rows above

CREATE TABLE t2 SELECT * FROM t1 ORDER BY rand();

--echo # Tree-walking query. We turn off the Query Cache: indeed
--echo # sometimes pb2 enables Query Cache and as we run twice the
--echo # same query the 2nd may not actually be executed so the value
--echo # of Created_tmp_tables displayed at end becomes "one less").

let $query=
WITH RECURSIVE tree_of_a AS
(
SELECT *, cast(id AS char(200)) AS path FROM t2 WHERE name="A"
UNION ALL
SELECT t2.*, concat(tree_of_a.path,",",t2.id) FROM t2 JOIN tree_of_a ON
t2.id=tree_of_a.leftpar
UNION ALL
SELECT t2.*, concat(tree_of_a.path,",",t2.id) FROM t2 JOIN tree_of_a ON
t2.id=tree_of_a.rightpar
)
SELECT * FROM tree_of_a;

--echo # Note that without ORDER BY, order of rows would be random as BNL
--echo # implies that the randomized t2 is the driving table in the
--echo # joining of rows.

--replace_column 10 #
eval EXPLAIN extended $query ORDER BY path;

eval $query ORDER BY path;

--echo # Equivalent query with one single recursive query block:

WITH RECURSIVE tree_of_a AS
(
SELECT *, cast(id AS char(200)) AS path FROM t2 WHERE name="A"
UNION ALL
SELECT t2.*, concat(tree_of_a.path,",",t2.id) FROM t2 JOIN tree_of_a ON
(t2.id=tree_of_a.leftpar OR t2.id=tree_of_a.rightpar)
)
SELECT * FROM tree_of_a
ORDER BY path;

--echo # Demonstrate a case where an index is automatically created on
--echo # the derived table and used to read this table in the outer
--echo # query (but correctly not used to read it in the recursive
--echo # query).

let $query=
WITH RECURSIVE tree_of_a AS
(
SELECT *, cast(id AS char(200)) AS path FROM t2 WHERE name="A"
UNION ALL
SELECT t2.*, concat(tree_of_a.path,",",t2.id) FROM t2 JOIN tree_of_a ON
t2.id=tree_of_a.leftpar
UNION ALL
SELECT t2.*, concat(tree_of_a.path,",",t2.id) FROM t2 JOIN tree_of_a ON
t2.id=tree_of_a.rightpar
)
SELECT * FROM tree_of_a WHERE id=2;

--replace_column 10 #
eval EXPLAIN $query;

eval $query;

DROP TABLE t1,t2;

let $query=
WITH RECURSIVE cte AS
(
  SELECT 1 AS n UNION ALL
  SELECT n+1 FROM cte WHERE n<10000
)
SELECT sum(cte1.n*cte2.n*cte3.n)=2490508525950000
FROM cte cte1, cte cte2, cte cte3
WHERE cte1.n=cte2.n+10 AND cte2.n+20=cte3.n;

--replace_column 10 #
eval EXPLAIN $query;
eval $query;

--echo #
--echo # Transitive closure
--echo #

CREATE TABLE nodes(id int);
CREATE TABLE arcs(from_id int, to_id int);
INSERT INTO nodes VALUES(1),(2),(3),(4),(5),(6),(7),(8);
INSERT INTO arcs VALUES(1,3), (3,6), (1,4), (4,6), (6,2), (2,1);

--echo # UNION ALL leads to infinite loop as 1 is reachable from 1;
--echo # so we stop it with a maximum depth 8 (8 nodes in graph)

WITH RECURSIVE cte AS
(
  SELECT id, 0 AS depth FROM nodes WHERE id=1
  UNION ALL
  SELECT to_id, depth+1 FROM arcs, cte
  WHERE from_id=cte.id AND depth<8
)
SELECT count(*), max(depth) FROM cte;

--echo # Can use cycle detection:

WITH RECURSIVE cte AS
(
  SELECT id, cast(id AS char(200)) AS path, 0 AS is_cycle
  FROM nodes WHERE id=1
  UNION ALL
  SELECT to_id, concat(cte.path, ",", to_id), find_in_set(to_id, path)
  FROM arcs, cte
  WHERE from_id=cte.id AND is_cycle=0
)
SELECT * FROM cte;

--echo # It is simpler with DISTINCT:
WITH RECURSIVE cte AS
(
  SELECT id FROM nodes WHERE id=1
  UNION
  SELECT to_id FROM arcs, cte WHERE from_id=cte.id
)
SELECT * FROM cte;

DROP TABLE nodes, arcs;

--echo # Hash field and MEMORY don't work together. Make long distinct
--echo # key to force hash field, to see if it switches to InnoDB.

--echo # Not too long key (500 bytes in latin1)
WITH RECURSIVE cte AS
 (
  SELECT 1 AS n,
  repeat('a',500) AS f, '' AS g,
  '' AS h, '' AS i
  UNION
  SELECT n+1,
  '','','',''
  FROM cte WHERE n<100)
SELECT sum(n) FROM cte;

SHOW STATUS LIKE 'Created_tmp_disk_tables';

--echo # Too long key (>3000 bytes in latin1)
WITH RECURSIVE cte AS
 (
  SELECT 1 AS n,
  repeat('a',500) AS f, repeat('a',500) AS g,
  repeat('a',500) AS h, repeat('a',500) AS i,
  repeat('a',500) AS j, repeat('a',500) AS k,
  repeat('a',500) AS l, repeat('a',500) AS m
  UNION
  SELECT n+1,
  '','','','','','','',''
  FROM cte WHERE n<100)
SELECT sum(n) FROM cte;

--echo #
--echo # In query planning, the recursive reference's row count is
--echo # said to be the estimated row count of all non-recursive query
--echo # blocks

CREATE TABLE t1(a int);
--echo # 15 rows:
INSERT INTO t1 VALUES (), (), (), (), (), (), (), (), (), (), (), (),
(), (), ();
ANALYZE TABLE t1;
--echo # EXPLAIN says: in non-recursive QB we'll read 15 rows of t1,
--echo # in recursive QB we'll read 15 rows of qn, keep only 0.33
--echo # due to WHERE, that makes 4 (due to rounding), and in the
--echo # derived table we'll thus have 15+4=19. That ignores
--echo # next repetitions of the recursive QB which are unpredictable.
EXPLAIN WITH RECURSIVE qn AS
(SELECT 1 AS a FROM t1 UNION ALL SELECT a+1 FROM qn WHERE qn.a<100)
SELECT * FROM qn;
EXPLAIN WITH RECURSIVE qn AS
(SELECT 1 AS a FROM t1 UNION DISTINCT SELECT a+1 FROM qn WHERE qn.a<100)
SELECT * FROM qn;
DROP TABLE t1;

SHOW STATUS LIKE 'Created_tmp_disk_tables';

flush STATUS;

WITH RECURSIVE q (b) AS
(SELECT 1 UNION ALL SELECT 1+b FROM q WHERE b<2000)
SELECT min(b),max(b),avg(b) FROM q;
SHOW STATUS LIKE 'Created_tmp_disk_tables';

--echo # Test when conversion to InnoDB affects recursive references which
--echo # are not open yet (those of q1):
flush STATUS;
WITH RECURSIVE q (b) AS
(SELECT 1 UNION ALL SELECT 1+b FROM q WHERE b<2000)
SELECT min(q.b),max(q.b),avg(q.b) FROM q, q AS q1;
SHOW STATUS LIKE 'Created_tmp_disk_tables';

--echo # Same, but make q1 the writer; this is to test overflow when
--echo # the writer isn't first in the 'tmp_tables' list

flush STATUS;
WITH RECURSIVE q (b) AS
(SELECT 1 UNION ALL SELECT 1+b FROM q WHERE b<2000)
SELECT min(q.b),max(q.b),avg(q.b) FROM q RIGHT JOIN q AS q1 ON 1;
SHOW STATUS LIKE 'Created_tmp_disk_tables';

--echo # Test when outer query reads CTE with an index.
--echo # Overflow doesn't happen at same row as queries above, as this
--echo # table has an index which makes it grow faster.

let $query=
WITH RECURSIVE q (b) AS
(SELECT 1 UNION ALL SELECT 1+b FROM q WHERE b<2000)
SELECT min(b),max(b),avg(b) FROM q WHERE b=300;

eval EXPLAIN $query;
SHOW STATUS LIKE 'Created_tmp_disk_tables';
eval $query;
SHOW STATUS LIKE 'Created_tmp_disk_tables';

--echo # Verify that rows come out in insertion order.
--echo # If they didn't, the sequences of @c and of 'b'
--echo # would not be identical and the sum wouldn't be
--echo # 1^2 + ... + 2000^2 = n(n+1)(2n+1)/6 = 2668667000

SET @c:=1;
flush STATUS;
WITH RECURSIVE q (b, c) AS
(SELECT 1, 1 UNION ALL SELECT (1+b), (@c:=(@c+1)) FROM q WHERE b<2000)
SELECT sum(b*c) FROM q;
SHOW STATUS LIKE 'Created_tmp_disk_tables';

--echo #
--echo # Bug#23495283 WL3634:ASSERTION `0' FAILED IN FIELD* ITEM::TMP_TABLE_FIELD_FROM_FIELD_TYPE
--echo #

CREATE TABLE t1(c1 DATETIME, c2 INT, KEY(c1));

--error ER_WRONG_NUMBER_OF_COLUMNS_IN_SELECT
WITH RECURSIVE cte AS ( SELECT a.c1 AS field1, 0 AS cycle FROM (t1 AS a)
UNION ALL SELECT b.c2 FROM cte AS a JOIN t1 AS b) SELECT * FROM cte;

DROP TABLE t1;

--echo #
--echo # Bug#23645090 WL3634: INVALID WRITE AND READ VALGRIND ERRORS
--echo #

CREATE TABLE A (
  col_date date DEFAULT NULL,
  col_datetime_key datetime DEFAULT NULL,
  col_time_key time DEFAULT NULL,
  col_varchar_key varchar(1) DEFAULT NULL,
  col_int_key int(11) DEFAULT NULL,
  col_blob_key blob,
  col_varchar varchar(1) DEFAULT NULL,
  col_date_key date DEFAULT NULL,
  col_time time DEFAULT NULL,
  col_blob blob,
  pk int(11) NOT NULL AUTO_INCREMENT,
  col_int int(11) DEFAULT NULL,
  col_datetime datetime DEFAULT NULL,
  PRIMARY KEY (pk),
  KEY col_datetime_key (col_datetime_key),
  KEY col_time_key (col_time_key),
  KEY col_varchar_key (col_varchar_key),
  KEY col_int_key (col_int_key),
  KEY col_blob_key (col_blob_key(255)),
  KEY col_date_key (col_date_key)
) DEFAULT CHARSET=latin1;

CREATE TABLE AA (
  col_varchar varchar(1) DEFAULT NULL,
  col_date date DEFAULT NULL,
  col_varchar_key varchar(1) DEFAULT NULL,
  col_date_key date DEFAULT NULL,
  col_datetime_key datetime DEFAULT NULL,
  col_time_key time DEFAULT NULL,
  pk int(11) NOT NULL AUTO_INCREMENT,
  col_time time DEFAULT NULL,
  col_int_key int(11) DEFAULT NULL,
  col_datetime datetime DEFAULT NULL,
  col_int int(11) DEFAULT NULL,
  col_blob blob,
  col_blob_key blob,
  PRIMARY KEY (pk),
  KEY col_varchar_key (col_varchar_key),
  KEY col_date_key (col_date_key),
  KEY col_datetime_key (col_datetime_key),
  KEY col_time_key (col_time_key),
  KEY col_int_key (col_int_key),
  KEY col_blob_key (col_blob_key(255))
) DEFAULT CHARSET=latin1;

CREATE TABLE BB (
  col_date date DEFAULT NULL,
  col_blob_key blob,
  col_time time DEFAULT NULL,
  col_varchar_key varchar(1) DEFAULT NULL,
  col_varchar varchar(1) DEFAULT NULL,
  col_blob blob,
  pk int(11) NOT NULL AUTO_INCREMENT,
  col_int_key int(11) DEFAULT NULL,
  col_datetime datetime DEFAULT NULL,
  col_time_key time DEFAULT NULL,
  col_datetime_key datetime DEFAULT NULL,
  col_date_key date DEFAULT NULL,
  col_int int(11) DEFAULT NULL,
  PRIMARY KEY (pk),
  KEY col_blob_key (col_blob_key(255)),
  KEY col_varchar_key (col_varchar_key),
  KEY col_int_key (col_int_key),
  KEY col_time_key (col_time_key),
  KEY col_datetime_key (col_datetime_key),
  KEY col_date_key (col_date_key)
) AUTO_INCREMENT=11 DEFAULT CHARSET=latin1;

CREATE TABLE D (
  col_varchar_key varchar(1) DEFAULT NULL,
  col_datetime datetime DEFAULT NULL,
  col_date_key date DEFAULT NULL,
  col_int int(11) DEFAULT NULL,
  col_time time DEFAULT NULL,
  col_blob blob,
  col_int_key int(11) DEFAULT NULL,
  col_blob_key blob,
  col_varchar varchar(1) DEFAULT NULL,
  col_datetime_key datetime DEFAULT NULL,
  col_date date DEFAULT NULL,
  col_time_key time DEFAULT NULL,
  pk int(11) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (pk),
  KEY col_varchar_key (col_varchar_key),
  KEY col_date_key (col_date_key),
  KEY col_int_key (col_int_key),
  KEY col_blob_key (col_blob_key(255)),
  KEY col_datetime_key (col_datetime_key),
  KEY col_time_key (col_time_key)
) DEFAULT CHARSET=latin1;

WITH RECURSIVE cte AS (
SELECT    alias1 . `col_blob_key` AS field1, 0 AS cycle
FROM ( BB AS alias1 , ( D AS alias2 , AA AS alias3 ) )
WHERE (
alias1 . pk = 225
OR ( alias1 . col_int_key = 69 AND alias1 . col_blob_key = 'p' )
)
UNION ALL
SELECT t1.pk, t2.cycle
FROM cte AS t2 JOIN A AS t1
WHERE t2.field1 = t1.`col_int_key`
AND t2.cycle =1 ) SELECT  * FROM cte;

DROP TABLE IF EXISTS A, AA, BB, D;

--echo #
--echo # Bug#24962600 WL3634: SIG 11 IN HEAP_RRND AT STORAGE/HEAP/HP_RRND.C
--echo #

create table t1(a int);

# empty table
with recursive cte as (select * from t1 union select * from cte)
 select * from cte;
insert into t1 values(1),(2);
# always-false WHERE
with recursive cte as (select * from t1 where 0 union select * from cte)
 select * from cte;
# no matching rows
with recursive cte as (select * from t1 where a>3 union select * from cte)
 select * from cte;

drop table t1;


--echo #
--echo # Bug#26501463 WL10792: ASSERTION `!TABLE->HAS_NULL_ROW()' FAILED
--echo #

CREATE TABLE D (col_int INT);

CREATE TABLE C (
  col_int2 INT,
  pk INT NOT NULL,
  col_int INT,
  PRIMARY KEY (pk)
);
INSERT INTO C VALUES
(7,1,3),(7,2,3),(5,3,4),(1,4,6),(5,5,2),
(5,6,9),(4,7,9),(7,8,3),(3,9,0),(5,10,3);

CREATE TABLE BB (
  pk INT NOT NULL,
  col_int INT,
  PRIMARY KEY (pk)
);
INSERT INTO BB VALUES (1,0),(2,6),(3,2),(4,5),(5,0);

WITH RECURSIVE cte AS (
SELECT alias2 . col_int2 AS field1 FROM
D AS alias1 RIGHT  JOIN
  ( ( C AS alias2 LEFT  JOIN BB AS alias3
      ON (( alias3 . pk = alias2 . col_int ) AND ( alias3 . pk = alias2 . pk ) ) ) )
ON (alias3 . col_int <> alias2 . col_int2 )
HAVING field1 <= 0
UNION
SELECT cte.field1 FROM cte
)
SELECT * FROM cte;

DROP TABLE BB,C,D;

--echo #
--echo # Bug#26556025 ASSERTION `!SELECT_LEX->IS_RECURSIVE() || !TMP_TABLES' FAILED.
--echo #

SET SQL_BUFFER_RESULT = 1;

WITH RECURSIVE cte AS
 (SELECT 1 AS n UNION SELECT n+1 FROM cte WHERE n<3)
SELECT * FROM cte;

WITH RECURSIVE cte AS
 (SELECT 1 AS n UNION ALL SELECT n+1 FROM cte WHERE n<3)
SELECT * FROM cte;

SET SQL_BUFFER_RESULT = DEFAULT;
