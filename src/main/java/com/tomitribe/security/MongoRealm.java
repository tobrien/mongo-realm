package com.tomitribe.security;


import com.mongodb.*;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.realm.RealmBase;

import java.net.UnknownHostException;
import java.security.Principal;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.text.Format;
import java.util.ArrayList;
import java.util.Iterator;

public class MongoRealm extends RealmBase {


    protected String mongoClientURI = "mongodb://localhost/";

    protected String database = "security_realm";

    protected String userCollection = "user";

    protected String usernameField = "username";

    protected String credentialsField = "credentials";

    protected String rolesField = "roles";

    protected String roleNameField = "name";

    protected static MongoClient mongoClient = null;


    /**
     * Descriptive information about this Realm implementation.
     */
    protected static final String info =
            "com.tomitribe.security.MongoRealm/1.0";


    /**
     * Descriptive information about this Realm implementation.
     */
    protected static final String name = "MongoRealm";


    /**
     * Return the URI to use to connect to the database.
     */
    public String getMongoClientURI() {
        return mongoClientURI;
    }

    /**
     * Set the URI to use to connect to the database.
     *
     * @param mongoClientURI The new connection URI
     */
    public void setMongoClientURI(String mongoClientURI) {
        this.mongoClientURI = mongoClientURI;
    }

    public String getDatabase() {
        return database;
    }

    public void setDatabase(String database) {
        this.database = database;
    }

    public String getUserCollection() {
        return userCollection;
    }

    public void setUserCollection(String userCollection) {
        this.userCollection = userCollection;
    }

    public String getUsernameField() {
        return usernameField;
    }

    public void setUsernameField(String usernameField) {
        this.usernameField = usernameField;
    }

    public String getCredentialsField() {
        return credentialsField;
    }

    public void setCredentialsField(String credentialsField) {
        this.credentialsField = credentialsField;
    }

    public String getRolesField() {
        return rolesField;
    }

    public void setRolesField(String rolesField) {
        this.rolesField = rolesField;
    }

    public String getRoleNameField() {
        return roleNameField;
    }

    public void setRoleNameField(String roleNameField) {
        this.roleNameField = roleNameField;
    }

    @Override
    public String getInfo() {
        return info;
    }

    @Override
    protected String getName() {
        return name;
    }

    /**
     * Return the Principal associated with the specified username and
     * credentials, if there is one; otherwise return <code>null</code>.
     * <p/>
     * If there are any errors with the MongoDB connection, executing
     * the query or anything we return null (don't authenticate). This
     * event is also logged, and the connection will be closed so that
     * a subsequent request will automatically re-open it.
     *
     * @param username    Username of the Principal to look up
     * @param credentials Password or other credentials to use in
     *                    authenticating this username
     */
    @Override
    public synchronized Principal authenticate(String username, String credentials) {

        // No user or no credentials
        // Can't possibly authenticate, don't bother the database then
        if (username == null || credentials == null) {
            return null;
        }

        // Look up the user's credentials
        String dbCredentials = getPassword(username);

        if (dbCredentials != null) {

            // Validate the user's credentials
            boolean validated = false;
            if (hasMessageDigest()) {
                // Hex hashes should be compared case-insensitive
                validated = (digest(credentials).equalsIgnoreCase(dbCredentials));
            } else {
                validated = (digest(credentials).equals(dbCredentials));
            }

            if (validated) {

                containerLog.info(String.format("Authentication Success for %s", username));
            } else {

                containerLog.info(String.format("Authentication Failure for %s", username));
                return (null);
            }

            ArrayList<String> roles = getRoles(username);

            // Create and return a suitable Principal for this user
            return (new GenericPrincipal(username, credentials, roles));

        } else {


            containerLog.warn(String.format("Credentials for %s could not be located", username));

            // Worst case is if there is no matching user record or password
            // The Tomcat API throws null around too much - this follows a pattern
            // established by the JDBCRealm
            return null;
        }
    }

    private DB openMongoDB() throws UnknownHostException {

        if (mongoClient == null) {
            mongoClient = new MongoClient(new MongoClientURI(getMongoClientURI()));
        }
        return mongoClient.getDB(getDatabase());
    }


    @Override
    protected String getPassword(String username) {

        String credentials = null;

        try {

            DB db = openMongoDB();
            DBCollection userCol = db.getCollection(userCollection);
            BasicDBObject query = new BasicDBObject(usernameField, username);
            DBObject obj = userCol.findOne(query);

            if (obj == null) {
                // Log the problem for posterity
                containerLog.warn(String.format("Unknown username exception, Username: %s", username));
                return null;
            }

            credentials = (String) obj.get(getCredentialsField());

        } catch (UnknownHostException e) {

            // Log the problem for posterity
            containerLog.error(String.format("Unknown host exception, Mongo URI: %s", getMongoClientURI()), e);

        }

        return credentials;
    }

    @Override
    protected Principal getPrincipal(String username) {

        // Create and return a suitable Principal for this user
        return (new GenericPrincipal(username, getPassword(username), getRoles(username)));

    }

    /**
     * Return the roles associated with the gven user name.
     */
    protected ArrayList<String> getRoles(String username) {

        if (allRolesMode != AllRolesMode.STRICT_MODE && !isRoleStoreDefined()) {
            // Using an authentication only configuration and no role store has
            // been defined so don't spend cycles looking
            return null;
        }


        ArrayList<String> roles = new ArrayList<String>();

        try {

            DB db = openMongoDB();
            DBCollection userCol = db.getCollection(userCollection);
            BasicDBObject query = new BasicDBObject(usernameField, username);
            DBObject userObj = userCol.findOne(query);

            if (userObj == null) {
                // Log the problem for posterity
                containerLog.warn(String.format("Unknown username exception, Username: %s", username));
                return roles;
            }

            BasicDBList rolesList = (BasicDBList) userObj.get(rolesField);

            Iterator roleIterator = rolesList.iterator();
            while (roleIterator.hasNext()) {
                BasicDBObject roleObj = (BasicDBObject) roleIterator.next();
                roles.add((String) roleObj.get(getRoleNameField()));
            }

        } catch (UnknownHostException e) {

            // Log the problem for posterity
            containerLog.error(String.format("Unknown host exception, Mongo URI: %s", getMongoClientURI()), e);


        }

        return roles;
    }

    private boolean isRoleStoreDefined() {
        return rolesField != null || roleNameField != null;
    }


}
