package dabao

import (
  "net/http"
  "html/template"
  "time"

  "appengine"
  "appengine/user"
  "appengine/datastore"
)

type Dabao struct {
  Id int64
  Organizer string
  Description string
  CreationDate time.Time
}

func init() {
  http.HandleFunc("/", root)
  http.HandleFunc("/newDabao", createDabao)
}

// dabaoKey returns the key used for all dabao sessions
func dabaoKey(c appengine.Context) *datastore.Key {
  return datastore.NewKey(c, "Dabao", "dabao_0.1", 0, nil)
}

func createDabao(w http.ResponseWriter, r *http.Request) {
  c := appengine.NewContext(r)  
  d := Dabao {
    Description: r.FormValue("Description"),
    CreationDate: time.Now(),
  }
  

  u := user.Current(c)
  if u != nil {
    d.Organizer = u.String()
  } else {
    d.Organizer = "Anonymous"
  }

  key := datastore.NewIncompleteKey(c, "Dabao", dabaoKey(c))
  var _, err = datastore.Put(c, key, &d)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  http.Redirect(w, r, "/", http.StatusFound)
}

func root(w http.ResponseWriter, r *http.Request) {
  c := appengine.NewContext(r)
  q := datastore.NewQuery("Dabao").Ancestor(dabaoKey(c)).Order("-CreationDate").Limit(10)

  allDabao := make([]Dabao, 0, 10)
  if _, err := q.GetAll(c, &allDabao); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  if err := dabaoTemplate.Execute(w, allDabao); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
  }
}

var dabaoTemplate = template.Must(template.New("dabao").Parse(`
<html>
  <head>
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css">
    <link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap-theme.min.css">
    <script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.2/js/bootstrap.min.js"></script>
    <title>Dabao Service</title>
  <head>
  <body>
  <div class="container">
    <div class="page-header"><h3>Dabao Service</h3></div>
    <form action="/newDabao" method="post">
      <div class="form-group">
        <label for="Description">Dabao details</label>
        <div><textarea id="Description" name="Description" class="form-control" rows="3"></textarea></div>
        <br />
        <div><input type="submit" class="btn btn-primary" value="New Dabao"></div>
      </div>
    </form>
    <hr class="divider" />
    {{range .}}
      <p><b>{{.Organizer}}</b> created:</p>
      <pre>{{.Description}}</pre>
    {{end}}
  </div>
  <footer class="footer">
    <p class="text-muted">Copyright <a href="https://github.com/hanxue">Lee Hanxue</a> 2015</p>
  </footer>
  </body>
</html>
`))
