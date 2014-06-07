<?php
class SESSIONObject {
    var $objectname='SESSIONObject';	
    function Save() {
        $_SESSION[$this->objectname] =$this;
        return true;
    }
}


class Authorizer extends SESSIONObject {
    var $objectname="Authorizer";
    var $loggedin;
    var $userdefaultpage;
    var $userobj;
    var $UserPermissions;
    var $login;
    var $loginname;
    var $failedloginattempt;
    var $failedlogincount;
    var $failedloginalert;
    var $destination;

    function WhatKindofLogin($userlogin) {
        $userlogin=trim($userlogin);
        $this->login=$userlogin;
        if (filter_var($userlogin, FILTER_VALIDATE_EMAIL))
            return array(0=> $userlogin, "type"=> "email", "email"=> $userlogin);
        elseif ($phoneno=is_phone_number($userlogin))
            return array(0=>$phoneno, "type"=>"phone" , "phone" => $phoneno);
        else return array(0=>$userlogin, "type"=>"school", "school"=> $userlogin);		
    }

    function IsLoggedIn() {
        if ($this->loggedin===true) {
            $this->ClearFailedLogin();
            return $this;
        }
        return ($this->IsSessLoggedIn() || $this->IsCookieLoggedIn());
    }

    function IsSessLoggedIn() {
        if (isset($_SESSION['Authorizer'])) { 
            $SessAuth=$_SESSION['Authorizer'];
            if ($SessAuth->loggedin) {
                $SessAuth->ClearFailedLogin();
                return $SessAuth;    
            }
        } else return false;
    }

    function IsCookieLoggedIn() {
        if (isset($_COOKIE['stay_valid']) && isset($_COOKIE['login']) ) { // check for saved cookies, one each for session id and login
            session_write_close();
            if (session_id($_COOKIE['stay_valid'])) {
                session_start();
                session_regenerate_id(true);
                $newsid=session_id();
                session_write_close();
                session_id($newsid);
                session_start();
                $renewedSession=$_SESSION['Authorizer'];
                if (is_object($renewedSession)) {
                    if ($renewedSession->loginname == $_COOKIE['login'])  //both cookies match for valid previous session
                        $renewedSession->SetPasswdCookies();
                    $renewedSession->ClearFailedLogin();
                    $renewedSession->Save();
                }
                return $renewedSession;
            } 
        }
        return false;		
    }

    function LogOut() {}

    function LogIn($login, $password, $dest='') {
        $this->loginname=$login;
        if ($this->SetAuthority($this->ValidatePassword($login, $password))) {
            $this->Save();
            return true;
        } else { //failed login
            $this->ClearAll(); //clear Session and Cookie
            $this->FailedLogin($login, $dest);
            return false;
        }
    }

    function SetPasswdCookies() {
        $a = session_id();
        if(empty($a)) {
            session_start();
            $a = session_id();
            if(empty($a)) $a=$_COOKIE['PHPSESSID'];
        }
        setcookie("stay_valid", $a, time()+15552000);
        setcookie("login", $this->loginname, time()+15552000);
    }

    function UnsetPasswdCookies() {
        setcookie("stay_valid", "");
        setcookie("login","");
    }

    function UserDefaultPage() {
        if (isset($this->userdefaultpage)) return $this->userdefaultpage;

    }

    function SetAuthority($userarray) {
        if (!$userarray) return false;
        $this->login ='user';
        $this->person_id=$userarray['person_id'];
        $user = new User;
        $user->Load(array('person_id'=>$userarray['person_id']));
        $user->SavetoSESSION();
        $this->loggedin=true;
        $this->Save();
        return true;		
    }

    function ValidatePassword($login, $password_attempt) {
        $user_array = what_kind_of_login($login);
        $stored_passwd = '*'; // In case the user is not found

        $hash_cost_log2 = 8;
        $hash_portable = FALSE;
        $fmhash = new PasswordHash($hash_cost_log2, $hash_portable);
        $query= "select person_id, password from persons where $user_array[type]=?";
        global $db;
        ($stmt = $db->prepare($query))
            || fail('MySQL prepare', $db->error);
        $stmt->bind_param('s', $user_array[0])
            || fail('MySQL bind_param', $db->error);
        $stmt->execute()
            || fail('MySQL execute', $db->error);
        $stmt->bind_result($person_id, $stored_passwd)
            || fail('MySQL bind_result', $db->error);		
        if (!$stmt->fetch() && $db->errno)
            fail('MySQL fetch', $db->error);		
        $stmt->close();
        $check = $fmhash->CheckPassword($password_attempt, $stored_passwd);
        unset($fmhash);
        if ($check)  $returnarray = array('person_id'=>$person_id);
        else $returnarray=false;

        return $returnarray;
    }

    function ClearAll() {
        $this->ClearSESSION();		
        $this->ClearCOOKIES();
        session_regenerate_id(true);
        return true;        
    }

    function Reset($dest='') {
    	$this->ClearAll();
    	$this->ReturntoIndex($dest);
    }

    function ReturntoIndex($dest='') {
        if (is_mobile_browser()) {
            header("Location:".MOBILE_URL_ROOT."index.php?r=".$dest);
            exit;
        } else {
            header("Location:index.php?r=".$dest);
            exit;
        }		
    }

    function ClearFailedLogin() {
        unset($this->failedloginattempt);
        unset($this->failedlogincount);
        unset($this->failedloginalert);
        $this->Save();
    }

    function FailedLogin($loginattempt='', $dest='') {
        $this->loggedin=false;
        unset($this->loginname);
        $this->failedloginalert=true;
        if ($loginattempt) {
            if ($this->failedloginattempt==$loginattempt) {
                $this->failedlogincount++;
                if ($this->failedlogincount >= 4) {
                    //send three bad attempts on same login, send warning
                    #####$this->SendWarning($loginattempt);
                }
            } else {
                $this->failedloginattempt=$loginattempt;
                $this->failedlogincount=1;
            }
        }
        if (!$dest) {
            $dest= $_SERVER['REQUEST_URI'];
            $this->destination=$dest;
        }

        $this->Save();
        $this->ReturntoIndex($dest);
    }

    function CheckforFailedLogin() {
	    if (isset($_SESSION['Authorizer'])) $oldAuth=$_SESSION['Authorizer'];
	    if (is_object($oldAuth) && $oldAuth->failedloginattempt) {
	        $this->failedloginattempt=$oldAuth->failedloginattempt;
	        $this->failedlogincount=$oldAuth->failedlogincount;
	        $this->failedloginalert=$oldAuth->failedloginalert;
	        return true;
	    } else return false;
    }

    function SavetoSESSION() {
        foreach ($this as $key=>$value)
            $_SESSION[$key]=$value;
        return true;
    }

    function ResetfromSESSION() {
        foreach ($_SESSION as $key=>$value)
            $this->$key=$value;
        return true;
    }

    function ClearSESSION() {
        foreach ($_SESSION as $key=>$value)
            unset($_SESSION[$key]);
        return true;		
    }

    function ClearCookies() {
        foreach ($_COOKIE as $key=>$value)
            if ($key=='PHPSESSID') continue;
            else setcookie($key,'');
        return true;
    }

} // end Authorizer class


class FooMoosDBObj {
    var $objectname='FooMoosDBObj';
    var $primary_keys=array();
    var $dbname;
    var $pdoname;

    public function __construct ($x='') {
        if ($x) {
            $this->tablehashprefix=$x;
            $this->table=$x."_".$this->generic_tablename;
        }
        if ($this->pdoname) { //setting a database connection
            global ${$this->pdoname};
            $this->pdo=&${$this->pdoname};                
        }
    }

    protected function ErrorLoc() {
        return "$this->objectname ";
    }

    protected function HasPrimaryKeySet() {
        $keysfull=true;
        if (is_array($this->primary_keys)) foreach ($this->primary_keys as $key) if (!isset($this->$key) || !$this->$key) $keysfull=false;
        return $keysfull;
    }        

    function CheckClass($classtype, $callingfunc='') {
        if (!$callingfunc) $callingfunc = "$this->objectname :: CheckClass";
        if (!class_exists($classtype)) {
            failorlog('Object error', "$callingfunc fail because class $classtype doesn't exist");
            return false;
        }
        return true;
    }	

    static function FilterObjArray($objarray, $filterarray='') {
        $Ks=array();
        foreach ($objarray as $K) {
            $filteredout=false;
            foreach ($filterarray as $attribute=>$value) {
                if (!($K->$attribute == $value)) {
                    $filteredout=true;
                    break;
                }
            }
            if (!$filteredout) $Ks[]=$K;
        }
        return $Ks;
    }

    function SavetoSESSION() {
        if ($this->pdo) unset($this->pdo); 
        // //This needs to be done because storing the pdo in the object
        // causes the save to $_SESSION to fail
        $_SESSION[$this->objectname] =$this;
        return true;
    }

    protected function UnsetPKs() {
        if (is_array($this->primary_keys)) foreach ($this->primary_keys as $pkname) unset($this->$pkname);
        else {
            $pkname=$this->primary_keys;
            unset($this->$pkname);
        }
        return true;	
    }

    protected function PKWhereClause() {
        $whereclause = '';
        $first = true;			
        foreach ($this->primary_keys as $key) {
            if ($this->$key) {
                $whereclause .= ($first) ? " $key='".addslashes($this->$key)."'" : " and $key='".addslashes($this->$key)."'" ;
                $first = false;
            } else {
                failorlog('Query build error', "error in $this->objectname :: PKWhereClause() , primary key '$key' empty, null or 0");
                return false;
            }
        }
        return $whereclause;
    }

    function CheckLoaded() {
        $notset=false;
        if (is_array($this->primary_keys)) {		
            foreach ($this->primary_keys as $pk) 
				if (!$this->$pk) $notset=true;                
        } elseif (!$this->primary_keys) $notset=true;
        foreach ($this->core_vars as $core_var)
            if (!$this->$core_var) $notset=true;
        return (!$notset);	
    }

    function Fill($values) { # used to fill the object with values without accessing the db
        $different=0;
        foreach ($values as $key => $value) {
            if ($this->$key != $value) $different=1;
            $this->$key = $value;
        }
        if ($different) return $different;
        else return 'allsame';
    }

    function AutoFill() {
        if ($_GET) {		
            $this->Fill($_GET);
            return true;
        }
        if ($_POST) { 
            $this->Fill($_POST);
            return true;
        }
        return false;
    }
} //end FooMoosDBObj


class PDOTableObj extends FooMoosDBObj {
    var $objectname="PDOTableObj";
    var $table;
    var $tablehashprefix;
    var $dbname;
    var $pdoname;
    var $generic_tablename='';
    var $pdo;

    # GetKids() is best used in a strictly one-to-many relationship, such as User-to-thatUser's Permissions.  
    function GetKids($objecttype, $objecthash='', $query='', $whereclause='where 1=1') {
        $whereclause.= ' and '.$this->PKWhereClause();
        if (!$this->CheckClass($objecttype)) return false;
        $templateobj= new $objecttype($objecthash);
        if (!$query) $query="select * from $templateobj->table $whereclause ";

        $statmnt =& pdoquery_n_exec($query, "$this->objectname::GetKids( $objecttype ) failed on query: $query", $this->pdoname);
        $results=$statmnt->fetchall(PDO::FETCH_ASSOC);

        $Ks=array();
        foreach ($results as $line) {
                $K = new $objecttype;
                $K->Fill($line);
                array_push($Ks, $K);
        }
        return $Ks; #an array of objects		
    }

    function Load() {
        if ($numargs = func_num_args()) {
            $args = func_get_arg(0); #read in variables
            if ($GLOBALS['debugger']) {
                dodumptostring($args, $str);
                addtoerrorlog("$this->objectname :: Load() pk array:".$str);
                echo "<br>$this->objectname args Load(): ";
                do_dump($args);
                echo '<br><br>';
            }
            if ($args) foreach ($args as $key => $value) $this->$key = $value;
        }
        $statmnt =& pdoquery_n_exec("select * from ".$this->table." where ".$this->PKWhereClause(), "$this->objectname::Load() ", $this->pdoname);
        $result=$statmnt->fetch(PDO::FETCH_ASSOC);

        if (is_array($result)) {  
            foreach ($result as $column => $column_val) $this->$column= $column_val;	
            return true;
        } else return false;
    }

    function FillFields() {
        if (!$this->fields && $this->table) {
                $query="select * from $this->table limit 1";
                $sttmnt = pdoquery_n_exec($query, "$this->objectname::FillFields() ", $this->pdoname);
                $dummy=$sttmnt->fetch(PDO::FETCH_ASSOC);
                $this->fields=array();
                foreach ($dummy as $field=>$dummyvalue) array_push($this->fields, $field);			
                return $this->fields;
        } else return $this->fields;		
    }

    function CurrentValues() {
        $this->fields = $this->FillFields();
        $CurrentValues = array();
        foreach ($this->fields as $field) {
                if (isset($this->$field)) { 
                        $CurrentValues[$field] = $this->$field;
                }
        } 
        return $CurrentValues;
    }

    protected function ResetfromKeys() {
        $keys=array();
        foreach ($this->primary_keys as $key) $keys[$key]=$this->$key;
        $this->Load($keys);
        return true;
    }

    protected function GetOldValues($query, $error_msg='',$dbname='') { //this function is just a wrapper for the database call, which in later classes will call a different database
        $statmnt=  pdoquery_n_exec($query, $error_msg." $this->objectname : GetOldValues()", $dbname);
        return $statmnt->fetch(PDO::FETCH_ASSOC);
    }

    function Save($NoReset=false) {	
        if ($this->HasPrimaryKeySet()) {// a primary key set, so this will be an update if there are fields altered
            $where_clause=" where ".$this->PKWhereClause();
            //first retrieve old values for comparison
            $oldinfo=$this->GetOldValues("select * from ".$this->table.$where_clause, "$this->objectname::Save() selecting old info to compare for update", $this->pdoname);

            $alteredfields=array();
            if (is_array($oldinfo)) foreach ($oldinfo as $field => $possiblyupdatedvalue) if ($possiblyupdatedvalue <> $this->$field) $alteredfields[$field]=$this->$field;

            if (count($alteredfields)) { // at least one field changed, must make an update	
                $setvaluestring="modified=CURRENT_TIMESTAMP";
                $historynote="Modified ".date("Y-m-d H:i:s ");
                array_walk($alteredfields, 'updatefieldswithequalsign');
                foreach ($alteredfields as $field=>$updatevalue) {
                    $setvaluestring.= ",".updatefieldswithequalsign($field,$updatevalue);
                    if ($oldinfo[$field]) $historynote.=", $field changed from ".mysql_real_escape_string($oldinfo[$field])." to ".mysql_real_escape_string($updatevalue);
                    else $historynote.=", $field set to ".mysql_real_escape_string($updatevalue);
                }
                $updatequery="update $this->table set ".$setvaluestring;
                if ($GLOBALS['debugger']) echo "<br><br> in $this->objectname::Save() Update query is: ".$updatequery."<br> historynote:\n".$historynote;

                $pdostatmnt = $this->pdo->query($updatequery.$where_clause);

                // TableObject updated!  now it's time to log it in the history table

                if (count($this->primary_keys)==1) $this->AddHistory( ($this->generic_tablename) ? $this->generic_tablename : $this->table, $this->{$this->primary_keys[0]}, $historynote );
                else $this->AddHistory( ($this->generic_tablename) ? $this->generic_tablename : $this->table, "$this->PKWhereClause()", $historynote);

                if (!$NoReset) $this->ResetfromKeys(); //simple reset
                return 'updated';			
            } else {//no changes to save
                //simple reset
                $keyname=$this->primary_keys[0];
                if ($NoReset) {}
                else $this->Load(array($this->primary_keys[0]=> $this->$keyname));			
                return 'no changes';
            } //end if/else $alteredfields
        } else { 
            //no pk means we're inserting
            if (!$this->fields) $this->fields=$this->FillFields();
            $insertfields = array();
            $insertvals =array();
            if (in_array('created',$this->fields)) {
                $insertfields[]='created';
                $insertvals[]='CURRENT_TIMESTAMP';
            }

            foreach ($this->fields as $field) if (isset($this->$field)) { 
                array_push($insertfields, $field);
                array_push($insertvals, "'".mysql_real_escape_string($this->$field)."'");
            } 

            $insertstatement="insert into $this->table (".join(",",$insertfields).") values (".join(",",$insertvals).")";
            $errormsg="$this->objectname :: Save() at Insert : $insertstatement";
            if ($GLOBALS['debugger']) {
                addtoerrorlog($errormsg);
                echo "<br><br> this->fields is :";
                do_dump($this->FillFields());
                echo '<br>pre-insert, $insertfields producing:<br>';
                print_r($insertfields);
                echo '<br>end of $insertfields<br>';
                echo '<br>pre-insert, $insertvals producing:<br>';
                print_r($insertvals);
                echo '<br>end of $insertvals<br>';                                                               
            }

            // Insert into DB 
            // The $pdo->query call seems to fail silently on bad mysql. hence the above debugging 
            // documentation. It should return a PDOStatement obj 
            // if successful; false otherwise.
            $statmnt=$this->pdo->query("insert into $this->table (".join(",",$insertfields).") values (".join(",",$insertvals).")");
            if (!$statmnt) {
                failorlog("Save/Insert failure", $errormsg);
                return false;
            }

            $last = $this->pdo->lastInsertId(); #auto-increment key!

            //simple reset
            if (!$NoReset) {
                if (count($this->primary_keys)==1) $this->Load(array($this->primary_keys[0]=> $last));
                else {
                    $this->{$this->primary_keys[0]}=$last;
                    $loadarray=array();
                    foreach ($this->primary_keys as $key) $loadarray["$key"]=$this->$key;
                    $this->Load($loadarray);
                }
            }
            return 'inserted';			
        }
    } //end Save()

    function AddHistory($table, $pkval, $changes_made) {
        if ($_SESSION['Authorizer']->login==="user") $utype="person";
        else $utype=$_SESSION['Authorizer']->login;
        $who= $_SESSION['Authorizer']->{$utype."_id"};
        if (!$who) $who="'no _id'";
        $historytable = ($this->dbname=='foomoos') ? "history": $this->tablehashprefix."_history";  
        if ($GLOBALS['debugger']) {
            echo "<br><br> Changes made = ".$changes_made;
            $query= sprintf('insert into '.$historytable.'  (table_name, table_key, who, who_type, what) 
                        values ("%s", %s, %s, "%s", "%s")',
                $table,
                $pkval,
                $who,
                $_SESSION['Authorizer']->login,
                $changes_made);
            echo "history insert is $query";
        }

        $this->pdo->query( sprintf('insert into '.$historytable.
            '(table_name, table_key, who, who_type, what) 
                values ("%s", %s, %s, "%s", "%s")',
            $table,
            $pkval,
            $who,
            $_SESSION['Authorizer']->login,
            $changes_made));
        return true;
    }

    
    # Find() and GetAll() are similar in use but take in different parameters for limiting the query.
    # Pass query variables to Find in an array:
    #
    #       eg.  Obj->Find(array('family_id' => 9 ));
    #
    # With GetAll you can use whole query clauses that will be tagged to the end of a where clause:
    #
    #       eg. Obj->GetAll(' and family_id = 9 and phone is not null and email like "%simon%" )
    function Find() {
        $numargs = func_num_args();
        $whereclause='';
        if ($numargs > 0) {
            $args = func_get_arg(0); #read in variable.
            if ($GLOBALS['debugger']) 
                addtoerrorlog("$this->objectname::FIND() args : ".dodumptostring(func_get_args(), $writestring));
            if (is_array($args)) {
                $first=true;
                foreach ($args as $key => $value) {
                    $value=mysql_real_escape_string($value);
                    $whereclause.= (($first) ? '': ' and ')." $key='$value' ";
                    $first=false;
                }
            }
        }

        $statmnt=& pdoquery_n_exec("select * from $this->table where $whereclause", "$this->objectname::Find()", $this->pdoname);

        if ($this->tablehashprefix) $results=$statmnt->fetchAll(PDO::FETCH_CLASS|PDO::FETCH_PROPS_LATE, $this->objectname, array($this->tablehashprefix));
        else $results=$statmnt->fetchAll(PDO::FETCH_CLASS, $this->objectname);

        return $results;           
    }

    function GetAll($querylimiters='', $include_deleted=false) {
        $whereclause=" where 1=1 ";
        if (!$include_deleted) $whereclause.=" and deleted is NULL ";
        if ($querylimiters) $whereclause.=" $querylimiters ";
        $statmnt=& pdoquery_n_exec("select * from $this->table $whereclause", "$this->objectname::GetAll()", $this->pdoname);
        if ($this->tablehashprefix) $results=$statmnt->fetchAll(PDO::FETCH_CLASS|PDO::FETCH_PROPS_LATE, $this->objectname, array($this->tablehashprefix));
        else $results=$statmnt->fetchAll(PDO::FETCH_CLASS, $this->objectname);
        return $results;           
    }

    //whereas Destroy() actually removes the row from the db table, Delete() merely timestamps the row's deleted column to mark deletion
    function Delete() {
        if (!$this->HasPrimaryKeySet()) {
            failorlog("Delete error","$this->objectname :: Delete() failed with an unset primary_key, pk ".$this->primary_keys[0]." = ".$this->{$this->primary_keys[0]});
            return false;
        }
        $query = "update $this->table set deleted=CURRENT_TIMESTAMP where ".$this->PKwhereclause();
        $result = pdoquery_n_exec($query, "$this->objectname :: Delete() query failed: $query");
        return $result;
    }

    function PDOChecknSet() {
        if (!is_object($this->pdo)) {
            // //setting a database connection
            global ${$this->pdoname};
            $this->pdo=&${$this->pdoname};
            return true;
        } else return false;
    }
    /*
    function Destroy() {
        if (!$this->HasPrimaryKeySet()) {
                failorlog("Delete error","$this->objectname :: Destroy() failed with an unset primary_key, pk ".$this->primary_keys[0]." = ".$this->{$this->primary_keys[0]});
                return false;
        }
        $query = "delete from ".$this->table." where ".$this->PKWhereClause();
        $result = query_or_error($query, "$this->objectname :: Destroy() query failed: $query");
        return $result;
    }
    */

} //end PDOTableObj

class TableObject extends PDOTableObj {
    var $objectname='TableObject';
    var $table;
    var $fields=array();
    var $name;
    var $kids=array();
    var $parents=array();
    var $editpermissions=array();
    var $core_vars=array();
    var $dbname='foomoos';
    var $pdoname='foomoos_pdo';
    var $pdo;
}

class LocatedObject extends TableObject {
    var $objectname="LocatedObject";
    var $full_address_field='full_address';

    function Save() {	
        $this->{$this->full_address_field}=$this->PrettyAddress();
        if ($this->{$this->full_address_field}) {
            (list($this->lat,$this->lng)=GMapsAddresstoLatLng($this->{$this->full_address_field})) || 
                    failorlog("Save error on Google Maps update","$this->objectname :: Save() ::GMapsAddresstoLatLng() call failed");
            $this->lat=round($this->lat, 9);	
            $this->lng=round($this->lng, 9);	
        }
        if ($this->phone) $this->phone=just_the_numbers($this->phone);
        if ($this->phone2) $this->phone2=just_the_numbers($this->phone2);
        if ($this->phone3) $this->phone3=just_the_numbers($this->phone3);
        if ($this->home_phone) $this->home_phone=just_the_numbers($this->home_phone);

        return call_user_func_array("parent::Save", func_get_args());
    }

    function PrettyAddress() {
        $return='';
        if (isset($this->address) && $this->address) $return.=$this->address."\n";
        if (isset($this->address2) && $this->address2) $return.=$this->address2."\n";
        if ((isset($this->city) && $this->city) && (isset($this->state) && $this->state)) $return.=$this->city.', '.$this->state.' ';
        elseif (isset($this->city) && $this->city) $return.=$this->city.' ';
        elseif (isset($this->state) && $this->state) $return.=$this->state.' ';
        return $return.$this->zip;
    }

    function PrettyAddressHTML() {
        $return='';
        if (isset($this->address) && $this->address) $return.=$this->address."<br>";
        if (isset($this->address2) && $this->address2) $return.=$this->address2."<br>";
        if ((isset($this->city) && $this->city) && (isset($this->state) && $this->state)) $return.=$this->city.', '.$this->state.' ';
        elseif (isset($this->city) && $this->city) $return.=$this->city.' ';
        elseif (isset($this->state) && $this->state) $return.=$this->state.' ';
        return $return.$this->zip."<br>";
    }	
}

class User extends LocatedObject {
    var $objectname='User';
    var $table='users';
    var $primary_keys = array('user_id');
    var $imgfolder = 'user/';

    var $first_name;
    var $last_name;
    var $type;

    function AutoFill() {
        $result=parent::AutoFill();
        if ($this->birth_year && $this->birth_month && $this->birth_day) $this->birthdate= $this->birth_year.'-'.$this->birth_month.'-'.$this->birth_day;
        return $result;
    }	
}

/*
For privacy reasons, photos will be kept OFF the server root.  If the server root is at ~/home/foomoos.com/, photos will be stored at ~/home/foomooslibrary/images.  IMG_LIB_ROOT 
and TEMP_PHOTO_FOLDER are defined in server_config.php
*/
class fmImage extends TableObject {
    var $objectname='fmImage';
    var $height;
    var $width;

    protected function XYfromImgHandle($imghandle) {
        $x=imagesx($imghandle);
        $y=imagesy($imghandle);
        if (intval($x)===intval($y)) return array(100,100);
        if (intval($x)>intval($y)) return array(100, round( (100 * intval($y) / intval($x)) ));
        else return array(round((100* intval($x) / intval($y))), 100);
    }

    function StoredImgFormats() {
		// when a photo gest uploaded, we store four different sizes of each picture for later use so that
		// never have to request a picture larger than we need
        $PhotoSizes = array(		
            'hdlarge' => array( 'maxsize' => '1280', 'type'=> 'jpg', 'suffix'=>'h'), 
            'large' => array( 'maxsize' => '900', 'type'=> 'jpg', 'suffix'=>'l'),
            'mobile' => array( 'maxsize' => '640', 'type'=> 'jpg', 'suffix'=>'m'),
            'thumb' => array( 'maxsize' => '200', 'type'=> 'jpg', 'suffix'=> 't'));
        return $PhotoSizes;
    }

    function getSupportedImageTypes() {
        //this library doesn't actually support wbmp images; this is solely for determining
        //what the current instance of PHP supports
        $aSupportedTypes = array();
            $aPossibleImageTypeBits = array(
            IMG_GIF=>'GIF',
            IMG_JPG=>'JPG',
            IMG_PNG=>'PNG',
            IMG_WBMP=>'WBMP' );
        foreach ($aPossibleImageTypeBits as $iImageTypeBits => $sImageTypeString)
            if (imagetypes() & $iImageTypeBits) $aSupportedTypes[] = $sImageTypeString;
        return $aSupportedTypes;
    }

    function GetImgType($imgpath) {
        switch (exif_imagetype($imgpath)) {
            case 1: //GIF
                return 'gif';
            case 2: //JPEG
                return 'jpg';
            case 3: //PNG
                return 'png';
            default:
                return false;	
        }
    }

    protected function PicNamefromURL_Aviary($url) {
		##################################################
		## ENTER YOUR OWN AVIARY KEY BELOW
        $aviary_apikey= "XXXXXXXXXXXXXXXX";
        return substr($url, (stripos($url, $aviary_apikey) + 10));	
    }

    // HEYYO!  fix this so non-image urls don't break everything
    function GetUrlPhoto($url) {
        return file_get_contents($url);
    }
    
    function UploadedXMLHTTPRequestPhoto() {
        $input = fopen("php://input", "r");
        $temp = tmpfile();
        $realSize = stream_copy_to_stream($input, $temp);
        fclose($input);

    }

    function NewImgHash($ownerclass, $ownerid, $phototempfilename='' ) {
        return hash('sha1', "$ownerclass $ownerid ".rand()." $phototempfilename ".time());
    }

    function MkImgDir($path) {
        // create the image directory if not present	
        if( file_exists( $path ) ) return true;
        else mkdir( $path , 0775, true );
        return true;
    }

    function PathfromHashName($namehash, $new=false) {
        // UrlfromNameHash() return converts the hashname into a path for the image
        // for instance, 3fa53bced76fbd720a9805417e29a1cd2c6a27d5 becomes
        // 3f/a5/3b/ce/3fa53bced76fbd720a9805417e29a1cd2c6a27d5.jpg
        $path = IMG_LIB_ROOT.substr($namehash, 0, 2).'/'.substr($namehash, 2, 2).'/'.substr($namehash, 4, 2).'/'.substr($namehash, 6, 2).'/';
        if ($new) $this->MkImgDir($path);
        return $path;
    }

    function ImgPathnFileName() {
        return $this->PathfromHashName($this->filename).$this->filename;
    }

    // After storing a temporary version of the image, we create four copies of different sizes/resolutions and save them on Amazon AWS
    function TmptoStored($ownerpk, $ownerclass, $tmppath) {
        $ImgHandlefromType="ImgHandlefrom".strtoupper($this->GetImgType($tmppath));
        unset($ImgObj);
        $ImgObj = new $ownerclass::$imgclusterclass;
        // $imglcusterclass is a static property of $ownerclass.  
        // $ImgObj ties a group object (eg. Family) to an image object, and its specific class will 
        // depend on the owner.  Family-owned images will
        // be served from a FamilysPic object, schools from SchoolsPic, etc.
        // For now, fill $ImgObj with the owner's details ($family_id, for instance)
        $Owner = new $ownerclass;
        $Owner->Load(array($Owner->primary_keys[0] => $ownerpk ));
        if (!$Owner->fmgrouphash) $Owner->SetFMGroupHash();
        $ImgObj->Fill( array($Owner->primary_keys[0] => $ownerpk));
        $this->filename=$this->NewImgHash($ownerclass, $ownerpk, $tmppath);
        $newpath=$this->PathfromHashName($this->filename, true);
        // also writing to AWS!
        if (!defined('AWSBUCKET')) define('AWSBUCKET', 'foomoosgroups');
        global $User;
        if (is_object($User) && $User->person_id) $creator_id=$User->person_id;
        else $creator_id='anon';
        $s3= new AmazonS3();
        $first=true;
        
        foreach ($this->StoredImgFormats() as $format => $properties) {
            $imghandle=$this->ResizeImgHandle($this->$ImgHandlefromType($tmppath), $properties['maxsize']);
            if ($first) {
                list($this->width, $this->height)=$this->XYfromImgHandle($imghandle);
                $first=false;
            }
            $CompleteImagePath=$newpath.$this->filename."_".$properties['suffix'].'.'.$properties['type'];
            if (isset($properties['writeto']) && $properties['writeto']) $WritetoType="Writeto".strtoupper($properties['writeto']);
            else $WritetoType="Writeto".strtoupper($properties['type']);

            if ($this->$WritetoType($imghandle, $CompleteImagePath)) {
                if (get_resource_type($imghandle)==='gd') imagedestroy($imghandle);
                $s3->batch()->create_object(AWSBUCKET, $Owner->objectname.'/'.$Owner->fmgrouphash.'/photos/'.$this->filename."_".$properties['suffix'].'.'.$properties['type'], 
                    array( 'fileUpload' => $CompleteImagePath,
                        'encryption' => 'AES256',
                        'meta' => array('ownerclass'=> $Owner->objectname,
                        'ownerpk' => $ownerpk,
                        'creator_id' => $creator_id )));
            }
            
        }

        $AWS_response = $s3->batch()->send();            
        if (!$AWS_response->areOK()) addtoerrorlog('Photo transfer to AWS failed , \n the batch-send response: '.dodumptostring($AWS_response,$yaddadadadad));
        unset($s3);

        $this->Save();
        $ImgObj->Fill(array( 'photo_id' => $this->{$this->primary_keys[0]},'filename' => $this->filename));
        $ImgObj->Save();
        unset($Owner);	
        return $ImgObj;
    }

    protected function ImgHandlefromPNG($imgpath) {
        ($big_img=imagecreatefrompng($imgpath)) or failorlog('photo error', "$this->objectname::ImgHandlefromPNG():imagecreatefrompng $imgpath failed");
        return $big_img;
    }

    protected function ImgHandlefromJPG($imgpath) {
        ($big_img=imagecreatefromjpeg($imgpath)) or failorlog('photo error', "$this->objectname::ImgHandlefromJPG():imagecreatefromjpeg $imgpath failed");
        return $big_img;
    }

    protected function ImgHandlefromGIF($imgpath) {
        ($big_img=imagecreatefromGIF($imgpath)) or failorlog('photo error', "$this->objectname::ImgHandlefromGIF():imagecreatefromgif $imgpath failed");
        return $big_img;
    }

    protected function ResizeImgHandle($imghandle, $maxsize) {
        //$maxsize: max pixel length in either direction of presumably rectangular new image
        // max pixel length of thumbnail in either direction
        $width=imagesx($imghandle);
        $height=imagesy($imghandle);
        if (intval($width) > intval($height)) {             //landscape
            if (intval($maxsize) >=  intval($width)) {      // image already smaller than max, lets not stretch it
                $thumb_width=$width;
                $thumb_height=$height;
            } else {
                $thumb_width = $maxsize;
                $thumb_height = $height / ($width / $thumb_width);
            }
        } else {                                            //portrait
            if (intval($maxsize) >=  intval($height)) {
                $thumb_width=$width;
                $thumb_height=$height;                
            } else {
                $thumb_height = $maxsize;
                $thumb_width = $width / ($height / $thumb_height);
            }
        }

        ($resized_img = imagecreatetruecolor($thumb_width,$thumb_height)) or failorlog('photo error', "$this->objectname::ResizeImgHandle():imagecreatetruecolor failed");

        (imagecopyresampled($resized_img, $imghandle, 0, 0, 0, 0, $thumb_width, $thumb_height, $width, $height)) or failorlog('photo error', "$this->objectname::ResizeImgHandle():imagecopyresampled failed");
        imagedestroy( $imghandle );
        return $resized_img;
    }

    protected function WritetoJPG ($imghandle, $newpath) {
        (imagejpeg( $imghandle, $newpath )) or failorlog('photo error', "$this->objectname :: WritetoJPG() : imagejpeg to $newpath failed");   
        imagedestroy( $imghandle );
        return true;
    }

    protected function WritetoPNG ($imghandle, $newpath) {
        (imagepng( $imghandle, $newpath )) or failorlog('photo error', "$this->objectname :: WritetoPNG() : imagepng failed");
        imagedestroy( $imghandle );
        return true;
    }
    
    function SavePHPInputStream($ownerpk, $ownerclass) {
        $tmpfilepath=$this->GetTempPhotoPath($ownerpk, $ownerclass).rand(); 
        $input = fopen("php://input", "r");
        $target = fopen($tmpfilepath, "w" );
        stream_copy_to_stream($input, $target);
        fclose($input);
        fclose($target);
        return $this->TmptoStored($ownerpk, $ownerclass, $tmpfilepath);
    }
    
    function SaveUploadedPhoto($ownerpk, $ownerclass, $file) {
        // the $file parameter should be either a file element from the $_FILES array -- eg $_FILES[0] -- 
        // or the tmp_name value, such $_FILES[$key]['tmp_name'] or $_FILES['mobileimageuploads']['tmp_name'][$key] 
        $tempfilepath=$this->GetTempPhotoPath($ownerpk, $ownerclass).rand();
        if (is_array($file) && array_key_exists('tmp_name', $file)) move_uploaded_file( $file['tmp_name'], $tempfilepath );
        else move_uploaded_file ($file, $tempfilepath);
        return $this->TmptoStored($ownerpk, $ownerclass, $tempfilepath);
    }

    function SaveAllPhotoUploads($ownerpk, $ownerclass) {
        $i=0;
        foreach( $_FILES as $file ) {
            $filename=strtolower($file['name']);
            if(strpos($filename,".jpg") || strpos($filename,".jpeg") || strpos($filename,".png") || strpos( $filename,".gif")) $imgcluster[$i++]=$this->SaveUploadedPhoto($ownerpk, $ownerclass, $file);
        }
        return $imgcluster;
    }
    
    function SaveAllPhotoUploads_Mobile($ownerpk, $ownerclass, $filearrayname) {
        $i=0;
        foreach ($_FILES[$filearrayname]["error"] as $key => $error) {
            if ($error == UPLOAD_ERR_OK) {
                $filename=strtolower($_FILES[$filearrayname]['name'][$key]);
                if(strpos($filename,".jpg") || strpos($filename,".jpeg") || strpos($filename,".png") || strpos( $filename,".gif")) 
                    $imgcluster[$i++]=$this->SaveUploadedPhoto($ownerpk, $ownerclass, $_FILES[$filearrayname]['tmp_name'][$key]);
            }
        }
        return $imgcluster;
    }

    function GetTempPhotoPath($ownerpk, $ownerclass) {
        $tmppath = TEMP_PHOTO_FOLDER.$ownerclass.'/'.$ownerpk.'/'.rand().'/';
        $this->MkImgDir($tmppath);
        return $tmppath;		
    }

    function SaveURLPhoto($ownerpk, $ownerclass, $url) {
        // if (!$newfilename) $newfilename=$this->PicNamefromURL_Aviary($url);
        //get the original
        $tmpfilepath=$this->GetTempPhotoPath($ownerpk, $ownerclass).rand();
        $newphoto = $this->GetUrlPhoto($url);
        $fp = fopen($tmpfilepath, "w");
        fwrite($fp, $newphoto);
        fclose($fp);

        return $this->TmptoStored($ownerpk, $ownerclass, $tmpfilepath);	
    }

    // CenteredSquarePNG() takes an image resource $imghandle and "squares" it by creating a square transparent background
    // and then centering the imghandle in the square
    function CenteredSquarePNG($imghandle) {
        $width=imagesx($imghandle);
        $height=imagesy($imghandle);
        if (intval($width) === intval($height)) return $imghandle; //already square
        $xshift=0;
        $yshift=0;
        if (intval($width) > intval($height)) { 		//landscape
            $newpng=imagecreatetruecolor($width, $width);
            $yshift=round((intval($width)-intval($height))/2);
        } else { 										// portrait
            $newpng=imagecreatetruecolor($height, $height);
            $xshift=round((intval($height)-intval($width))/2);
        }
        imagecolortransparent($newpng, imagecolorallocate($newpng,0,0,0));			
        imagecopyresampled($newpng, $imghandle,	 $xshift,$yshift,0,0,$width,$height,$width,$height);
        return $newpng;
    }
} //end fmImage class

class fmPhoto extends fmImage {
    var $objectname='fmPhoto';
    var $table='photos';
    var $primary_keys=array('photo_id');
    var $filename;

    function Load() {
        $return=call_user_func_array("parent::Load", func_get_args());
        $this->filepath=array();
        foreach ($this->StoredImgFormats() as $format=>$info)  
            $this->filepath[$format]=$this->filename.'_'.$info['suffix'].'.'.$info['type'];
        return $return;	
    }
}


/*
Suffixes for hashed photo filenames are:
h - hdlarge
l - large
m - mobile
t - thumb
i - mapicon
Map marker is a png image created from a mapicon overlaid on a frame-and-pointer image ($iconbg).  
*/

class Profile extends fmPhoto {
    var $objectname = 'Profile';

    function StoredImgFormats() {
        $PhotoSizes = 	array(		
            'hdlarge' => array( 'maxsize' => '1280', 'type'=> 'jpg', 'suffix'=>'h'), 
            'large' => array( 'maxsize' => '900', 'type'=> 'jpg', 'suffix'=>'l'),
            'mobile' => array( 'maxsize' => '640', 'type'=> 'jpg', 'suffix'=>'m'),
            'thumb' => array( 'maxsize' => '200', 'type'=> 'jpg', 'suffix'=> 't'),
            'mapicon' => array( 'maxsize' => '36', 'type'=> 'png', 'suffix'=>'i', 'writeto'=>'mapicon'),
            'mapiconHD' => array( 'maxsize' => '70', 'type' => 'png', 'suffix'=>'a', 'writeto'=>'mapiconHD'));
        return $PhotoSizes;
    }
    protected function WritetoMAPICONHD($imghandle,$newpath,$hd="HD") {
        $this->WritetoMAPICON($imghandle,$newpath,$hd);
    }

    protected function WritetoMAPICON ($imghandle, $newpath, $hd="") {
        $width=imagesx($imghandle);
        $height=imagesy($imghandle);
        $xoffset=0;
        $yoffset=0;
        if (intval($width) > intval($height)) $yoffset=round((intval($width)-intval($height))/2);
        if (intval($height) > intval($width)) $xoffset=round((intval($height)-intval($width))/2);

        $formats=$this->StoredImgFormats();		
        $maxsize=$formats["mapicon$hd"]['maxsize'];  //36 or 70 pixels, depending on if HD (retina display)
        $totaly=$maxsize + 16;			//all mapicon are 44w x 52t pixels, mapiconhd are 78w x 86t
        $totalx=$maxsize + 8;
        $centerx=round(intval($totalx) / 2 );

        $newimg=imagecreatetruecolor($totalx,$totaly);
        imagecolortransparent($newimg, imagecolorallocate($newimg,0,0,0));			

        //set colors for icon frame
        $bordercolor=imagecolorallocate($newimg, 168,69,62); //dark red
        $iconfill=imagecolorallocate($newimg, 255,132,122); //traffic orange-ish
        imagesetthickness($newimg,2);
        imagepolygon($newimg, array(
            1+$xoffset 			, $totaly-15-$height,
            $totalx-1-$xoffset	, $totaly-15-$height ,
            $totalx-1 -$xoffset	, $totaly-9,
            $centerx+7			, $totaly-9,
            $centerx 			, $totaly - 1,
            $centerx-7			, $totaly-9,
            1+$xoffset			, $totaly-9
            ), 7,$bordercolor);
        imagefilltoborder($newimg,$centerx, $totaly-20, $bordercolor,$iconfill);
        imagecopyresampled($newimg, $imghandle,4+$xoffset,$totaly-$height-12,0,0,$width,$height,$width,$height);
        return $this->WritetoPNG($newimg,$newpath);
    }

    //this next function for testing,debugging and composition purpose only
    function PolygonTest($inpath, $newpath, $imghandle='') {
        $this->WritetoMAPICONHD($this->ResizeImgHandle($this->ImgHandlefromJPG($inpath), '70'), $newpath);
        $this->WritetoMAPICON($this->ResizeImgHandle($this->ImgHandlefromJPG($inpath), '36'), 'bogus77.png');
    }
} // end Profile

class GroupsPic extends OwnersPic {
    var $objectname='GroupsPic';
    
    function GetAWSFileName($fmgrouphash) {
        if ($this->filename && $fmgrouphash) return $this->ownerclass.'/'.$fmgrouphash.'/photos/'.$this->filename;
        else return false;
    }
    
    //GetAllPicsofGroup() will also have the height / width ratio of the image included in 
    // the OwnersPic object array
    function GetAllPicsofGroup($GroupObj) {
        
    }
}

class SchoolsPic extends GroupsPic {
    var $objectname='SchoolsPic';
    var $table='schools_pics';
    var $primary_keys=array('sp_id');
    var $ownerclass='School';    
}

# external extensions
# the following classes extend other libraries
require_once 'lib/sdk-1.5.17.1/sdk.class.php';

class fmS3 extends AmazonS3 {
    function DefaultObjArray($user_id='anon', $meta=array(), $no_encrypt=false) {
        $returnarray=array('acl' => 'AmazonS3::ACL_PRIVATE');
        if ($no_encrypt) $returnarray['encryption']= 'AES256';
        if (!$meta['creator_id']) $meta['creator_id']=$user_id;
        $returnarray['meta']=$meta;
        return $returnarray;
    }
}


?>
