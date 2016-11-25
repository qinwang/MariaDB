#include <mysqld.h>
#include <mysql.h>
#include <xtrabackup.h>
#include <encryption_plugin.h>
#include <backup_copy.h>
#include <sql_plugin.h>
#include <sstream>
#include <common.h>


extern struct st_maria_plugin *mysql_optional_plugins[];
extern struct st_maria_plugin *mysql_mandatory_plugins[];
static void encryption_plugin_init(int argc, char **argv);

extern char *xb_plugin_load;
extern char *xb_plugin_dir;

const int PLUGIN_MAX_ARGS = 1024;

const char *QUERY_PLUGIN =
"SELECT plugin_name, plugin_library, @@plugin_dir"
" FROM information_schema.plugins WHERE plugin_type='ENCRYPTION'"
" AND plugin_status='ACTIVE'";

string encryption_plugin_config;

static void add_to_plugin_load_list(const char *plugin_def)
{
  opt_plugin_load_list_ptr->push_back(new i_string(plugin_def));
}

static char XTRABACKUP_EXE[] = "xtrabackup";

void encryption_plugin_backup_init(MYSQL *mysql)
{
  MYSQL_RES *result;
  MYSQL_ROW row;
  ostringstream oss;
  char *argv[PLUGIN_MAX_ARGS];
  int argc;


  if (mysql_query(mysql, QUERY_PLUGIN))
  {
    msg("xtrabackup : Error query %s failed - could not read plugin data : %s", 
      QUERY_PLUGIN,
      mysql_error(mysql));
    exit(EXIT_FAILURE);
  }

  result = mysql_store_result(mysql);
  if (!result)
  {
    msg("xtrabackup : Error : mysql_store_result failed : %s", mysql_error(mysql));
    exit(EXIT_FAILURE);
  }

  row = mysql_fetch_row(result);
  if (!row)
  {
    mysql_free_result(result);
    return;
  }

  char *name= row[0];
  char *library= row[1];
  char *dir= row[2];

#ifdef _WIN32
  for (char *p = dir; *p; p++)
    if (*p == '\\') *p = '/';
#endif

  string plugin_load(name);
  if (library)
    plugin_load += string("=") + library;

  oss << "plugin_load=" << plugin_load << endl;

  /* Required  to load the plugin later.*/
  add_to_plugin_load_list(plugin_load.c_str());
  strncpy(opt_plugin_dir, dir, FN_REFLEN);

  oss << "plugin_dir=" << '"' << dir << '"' << endl;

  char query[1024];
  snprintf(query, 1024, "SHOW variables like '%s_%%'", name);
	mysql_free_result(result);

  if (mysql_query(mysql, query))
  {
    msg("xtrabackup : Error query %s failed - could not read plugin vars : %s",
      query,  mysql_error(mysql));
    exit(EXIT_FAILURE);
  }

  result = mysql_store_result(mysql);
  if (!result)
  {
    msg("xtrabackup : mysql_store_result failed %s",
      query, mysql_error(mysql));
    exit(EXIT_FAILURE);
  }

  argc = 0;
  argv[argc++] =XTRABACKUP_EXE;
  while ((row = mysql_fetch_row(result)))
  {
    asprintf(&argv[argc], "%s=%s", row[0], row[1]);
    oss << argv[argc] << endl;
    argc++;
    if (argc == PLUGIN_MAX_ARGS - 1)
      break;
  }
  argv[argc] = 0;

  mysql_free_result(result);

  encryption_plugin_init(argc, argv);
  for (int i = 1; i < argc; i++)
    free(argv[i]);

  encryption_plugin_config = oss.str();
}

const char *encryption_plugin_get_config()
{
  return encryption_plugin_config.c_str();
}

void encryption_plugin_prepare_init(int argc, char **argv)
{
  if (!xb_plugin_load)
    return;

  add_to_plugin_load_list(xb_plugin_load);

  if (xb_plugin_dir)
    strncpy(opt_plugin_dir, xb_plugin_dir, FN_REFLEN);

  char **new_argv = new char *[argc + 1];
  new_argv[0] = XTRABACKUP_EXE;
  memcpy(&new_argv[1], argv, argc*sizeof(char *));

  encryption_plugin_init(argc+1, new_argv);

  delete[] new_argv;
}

static void encryption_plugin_init(int argc, char **argv)
{
  /* Patch optional and mandatory plugins, we only need to load the one in xb_plugin_load. */
  mysql_optional_plugins[0] = mysql_mandatory_plugins[0] = 0;
  plugin_init(&argc, argv, PLUGIN_INIT_SKIP_PLUGIN_TABLE);
}

