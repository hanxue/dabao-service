package dabao

import (
  "net/http"
  "html/template"
  "time"
  "fmt"
  "encoding/json"

  "appengine"
  "appengine/user"
  "appengine/datastore"
  // "golang.org/x/oauth2"
  "code.google.com/p/goauth2/oauth"
  "code.google.com/p/google-api-go-client/plus/v1"
  "github.com/gorilla/sessions"
)

type Dabao struct {
  Organizer string
  Description string
  CreationDate time.Time
}

func init() {
  http.HandleFunc("/", root)
  http.HandleFunc("/newDabao", createDabao)
  http.HandleFunc("/setup", setup)
  http.HandleFunc("/getCred", getCred)
}

type cred struct {
    clientID          string
    clientSecret      string
}

func setup(w http.ResponseWriter, r *http.Request) {
  c := appengine.NewContext(r)
  cred := &cred {
    clientID: "837492928-fakeclientid.apps.googleusercontent.com",
    clientSecret: "Y_jhSKjaAkjfakeClientSecret"}

  key := datastore.NewKey(c, "cred", "oauth", 0, nil)

  var _, err = datastore.Put(c, key, cred)
  if err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  fmt.Fprintf(w, `Successfully insert , %s : %s! `, key, cred)
}

func getCred(w http.ResponseWriter, r *http.Request) {
  c := appengine.NewContext(r)
  q := datastore.NewQuery("cred")
  qKeys := datastore.NewQuery("cred").KeysOnly()
  var creds []cred
  _, err := q.GetAll(c, &creds)
  if  err != nil {
    c.Errorf("getting everything: %v", err)
    return
  }
  allKeys, err := qKeys.GetAll(c, nil)
  if  err != nil {
    c.Errorf("getting keys: %v", err)
    return
  }

  fmtCred, _ := json.Marshal(&creds)
  fmt.Fprintf(w, "Stored credentials is: %s", fmtCred)
  fmtAllKeys, _ := json.Marshal(&allKeys)
  fmt.Fprintf(w, "All keys: %s", string(fmtAllKeys))
}

// config is the configuration specification supplied to the OAuth package.
var config = &oauth.Config{
  ClientId:     cred.clientID,
  ClientSecret: cred.clientSecret,
  // Scope determines which API calls you are authorized to make
  Scope:    "https://www.googleapis.com/auth/plus.login",
  AuthURL:  "https://accounts.google.com/o/oauth2/auth",
  TokenURL: "https://accounts.google.com/o/oauth2/token",
  // Use "postmessage" for the code-flow for server side apps
  RedirectURL: "postmessage",
}
var store = sessions.NewCookieStore([]byte(randomString(32)))
var indexTemplate = template.Must(template.ParseFiles("public/index.html"))

type Token struct {
  AccessToken string `json:"access_token"`
  TokenType   string `json:"token_type"`
  ExpiresIn   int    `json:"expires_in"`
  IdToken     string `json:"id_token"`
}

// ClaimSet represents an IdToken response.
type ClaimSet struct {
  Sub string
}

// exchange takes an authentication code and exchanges it with the OAuth
// endpoint for a Google API bearer token and a Google+ ID
func exchange(code string) (accessToken string, idToken string, err error) {
  // Exchange the authorization code for a credentials object via a POST request
  addr := "https://accounts.google.com/o/oauth2/token"
  values := url.Values{
    "Content-Type":  {"application/x-www-form-urlencoded"},
    "code":          {code},
    "client_id":     {clientID},
    "client_secret": {clientSecret},
    "redirect_uri":  {config.RedirectURL},
    "grant_type":    {"authorization_code"},
  }
  resp, err := http.PostForm(addr, values)
  if err != nil {
    return "", "", fmt.Errorf("Exchanging code: %v", err)
  }
  defer resp.Body.Close()

  // Decode the response body into a token object
  var token Token
  err = json.NewDecoder(resp.Body).Decode(&token)
  if err != nil {
    return "", "", fmt.Errorf("Decoding access token: %v", err)
  }

  return token.AccessToken, token.IdToken, nil
}

// decodeIdToken takes an ID Token and decodes it to fetch the Google+ ID within
func decodeIdToken (idToken string) (gplusID string, err error) {
  // An ID token is a cryptographically-signed JSON object encoded in base 64.
  // Normally, it is critical that you validate an ID token before you use it,
  // but since you are communicating directly with Google over an
  // intermediary-free HTTPS channel and using your Client Secret to
  // authenticate yourself to Google, you can be confident that the token you
  // receive really comes from Google and is valid. If your server passes the ID
  // token to other components of your app, it is extremely important that the
  // other components validate the token before using it.
  var set ClaimSet
  if idToken != "" {
    // Check that the padding is correct for a base64decode
    parts := strings.Split(idToken, ".")
    if len(parts) < 2 {
      return "", fmt.Errorf("Malformed ID token")
    }
    // Decode the ID token
    b, err := base64Decode(parts[1])
    if err != nil {
      return "", fmt.Errorf("Malformed ID token: %v", err)
    }
    err = json.Unmarshal(b, &set)
    if err != nil {
      return "", fmt.Errorf("Malformed ID token: %v", err)
    }
  }
  return set.Sub, nil
}

// index sets up a session for the current user and serves the index page
func index(w http.ResponseWriter, r *http.Request) *appError {
  // This check prevents the "/" handler from handling all requests by default
  if r.URL.Path != "/" {
    http.NotFound(w, r)
    return nil
  }

  // Create a state token to prevent request forgery and store it in the session
  // for later validation
  session, err := store.Get(r, "sessionName")
  if err != nil {
    log.Println("error fetching session:", err)
    // Ignore the initial session fetch error, as Get() always returns a
    // session, even if empty.
    //return &appError{err, "Error fetching session", 500}
  }
  state := randomString(64)
  session.Values["state"] = state
  session.Save(r, w)

  stateURL := url.QueryEscape(session.Values["state"].(string))

  // Fill in the missing fields in index.html
  var data = struct {
    ApplicationName, ClientID, State string
  }{applicationName, clientID, stateURL}

  // Render and serve the HTML
  err = indexTemplate.Execute(w, data)
  if err != nil {
    log.Println("error rendering template:", err)
    return &appError{err, "Error rendering template", 500}
  }
  return nil
}

// connect exchanges the one-time authorization code for a token and stores the
// token in the session
func connect(w http.ResponseWriter, r *http.Request) *appError {
  // Ensure that the request is not a forgery and that the user sending this
  // connect request is the expected user
  session, err := store.Get(r, "sessionName")
  if err != nil {
    log.Println("error fetching session:", err)
    return &appError{err, "Error fetching session", 500}
  }
  if r.FormValue("state") != session.Values["state"].(string) {
    m := "Invalid state parameter"
    return &appError{errors.New(m), m, 401}
  }
  // Normally, the state is a one-time token; however, in this example, we want
  // the user to be able to connect and disconnect without reloading the page.
  // Thus, for demonstration, we don't implement this best practice.
  // session.Values["state"] = nil

  // Setup for fetching the code from the request payload
  x, err := ioutil.ReadAll(r.Body)
  if err != nil {
    return &appError{err, "Error reading code in request body", 500}
  }
  code := string(x)

  accessToken, idToken, err := exchange(code)
  if err != nil {
          return &appError{err, "Error exchanging code for access token", 500}
  }
        gplusID, err := decodeIdToken(idToken)
  if err != nil {
          return &appError{err, "Error decoding ID token", 500}
  }

  // Check if the user is already connected
  storedToken := session.Values["accessToken"]
  storedGPlusID := session.Values["gplusID"]
  if storedToken != nil && storedGPlusID == gplusID {
    m := "Current user already connected"
    return &appError{errors.New(m), m, 200}
  }

  // Store the access token in the session for later use
  session.Values["accessToken"] = accessToken
  session.Values["gplusID"] = gplusID
  session.Save(r, w)
  return nil
}

// disconnect revokes the current user's token and resets their session
func disconnect(w http.ResponseWriter, r *http.Request) *appError {
  // Only disconnect a connected user
  session, err := store.Get(r, "sessionName")
  if err != nil {
    log.Println("error fetching session:", err)
    return &appError{err, "Error fetching session", 500}
  }
  token := session.Values["accessToken"]
  if token == nil {
    m := "Current user not connected"
    return &appError{errors.New(m), m, 401}
  }

  // Execute HTTP GET request to revoke current token
  url := "https://accounts.google.com/o/oauth2/revoke?token=" + token.(string)
  resp, err := http.Get(url)
  if err != nil {
    m := "Failed to revoke token for a given user"
    return &appError{errors.New(m), m, 400}
  }
  defer resp.Body.Close()

  // Reset the user's session
  session.Values["accessToken"] = nil
  session.Save(r, w)
  return nil
}

// people fetches the list of people user has shared with this app
func people(w http.ResponseWriter, r *http.Request) *appError {
  session, err := store.Get(r, "sessionName")
  if err != nil {
    log.Println("error fetching session:", err)
    return &appError{err, "Error fetching session", 500}
  }
  token := session.Values["accessToken"]
  // Only fetch a list of people for connected users
  if token == nil {
    m := "Current user not connected"
    return &appError{errors.New(m), m, 401}
  }

  // Create a new authorized API client
  t := &oauth.Transport{Config: config}
  tok := new(oauth.Token)
  tok.AccessToken = token.(string)
  t.Token = tok
  service, err := plus.New(t.Client())
  if err != nil {
    return &appError{err, "Create Plus Client", 500}
  }

  // Get a list of people that this user has shared with this app
  people := service.People.List("me", "visible")
  peopleFeed, err := people.Do()
  if err != nil {
    m := "Failed to refresh access token"
    if err.Error() == "AccessTokenRefreshError" {
      return &appError{errors.New(m), m, 500}
    }
    return &appError{err, m, 500}
  }
  w.Header().Set("Content-type", "application/json")
  err = json.NewEncoder(w).Encode(&peopleFeed)
  if err != nil {
    return &appError{err, "Convert PeopleFeed to JSON", 500}
  }
  return nil
}

// appHandler is to be used in error handling
type appHandler func(http.ResponseWriter, *http.Request) *appError

type appError struct {
  Err     error
  Message string
  Code    int
}

// serveHTTP formats and passes up an error
func (fn appHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
  if e := fn(w, r); e != nil { // e is *appError, not os.Error.
    log.Println(e.Err)
    http.Error(w, e.Message, e.Code)
  }
}

// randomString returns a random string with the specified length
func randomString(length int) (str string) {
  b := make([]byte, length)
  rand.Read(b)
  return base64.StdEncoding.EncodeToString(b)
}

func base64Decode(s string) ([]byte, error) {
  // add back missing padding
  switch len(s) % 4 {
  case 2:
    s += "=="
  case 3:
    s += "="
  }
  return base64.URLEncoding.DecodeString(s)
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
  u := user.Current(c)

  // Ensure user is logged in
  if u == nil {
    url, err := user.LoginURL(c, r.URL.String())
    if err != nil {
      http.Error(w, err.Error(), http.StatusInternalServerError)
      return
    }
    w.Header().Set("Location", url)
    w.WriteHeader(http.StatusFound)
    return
  }
  // if u == nil {
  //       url, _ := user.LoginURL(c, "/login")
  //       fmt.Fprintf(w, `<a href="%s">Sign in or register</a>`, url)
  //       return
  // }
  // url, _ := user.LogoutURL(c, "/logout")
  // fmt.Fprintf(w, `Welcome, %s! (<a href="%s">sign out</a>)`, u, url)

  allDabao := make([]Dabao, 0, 10)
  if _, err := q.GetAll(c, &allDabao); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
    return
  }

  if err := dabaoTemplate.Execute(w, allDabao); err != nil {
    http.Error(w, err.Error(), http.StatusInternalServerError)
  }
}

var dabaoTemplate = template.Must(template.ParseFiles("public/new-dabao.html"))

var notAuthenticatedTemplate = template.Must(template.New("login").Parse(`
<html><body>
You have currently not given permissions to access your data. Please authenticate this app with the Google OAuth provider.
<form action="/authorize" method="POST"><input type="submit" value="Ok, authorize this app with my id"/></form>
</body></html>
`));
