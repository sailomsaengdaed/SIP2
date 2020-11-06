using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
/////////////////////ADD USING
using System.Net;
using System.Net.Sockets;
using System.Globalization;
using SIP2;

namespace SIP2
{
    public class SIP2
    {
        //// Instance Variables/////////////////////////////////////////////////////////////////
        private IPAddress ipAddress;
        private IPEndPoint remoteEP;
        private Socket sender;//= new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

        private bool connected = false;
        private bool authorized = false;
        private int incrementer = 0;

        private string port = String.Empty;
        private string domain = String.Empty;
        private string username = String.Empty;
        private string password = String.Empty;
        private string extra_number = String.Empty;

        private delegate string SipFactory(string sipCommand);
        private SipFactory sipFactory;
        private bool hasChecksum;

        private string library = "";
        private string language = "001"; /* 001= english */

        /* Patron ID */
        private string patron = ""; /* AA */
        private string patronpwd = ""; /* AD */
        /* Terminal password */
        private string AC = ""; /*AC */

        /* Maximum number of resends allowed before get_message gives up */
        private int maxretry = 3;

        private string msgTerminator = "\r\n";

        private string fldTerminator = "|";

        /* Login Variables */
        private int UIDalgorithm = 0;   /* 0    = unencrypted, default */
        private int PWDalgorithm = 0;   /* undefined in documentation */
        private string scLocation = "";  /* Location Code */

        /* Debug */
        private bool debug = false;

        /* Public variables used for building messages */
        private string AO = "WohlersSIP";
        private string AN = "SIPCHK";

        /* Private variable to hold socket connection */
        private string socket;

        /* Sequence number counter */
        private int seq = -1;

        /* resend counter */
        private int retry = 0;

        /* Work area for building a message */
        private string msgBuild = "";
        private bool noFixed = false;
        //////PUBLIC/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        //////CONNECTION//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        public void SipConnection(string ip, string port, string username, string password, string extra_number = "")
        {
            this.domain = ip;
            this.port = port;
            this.username = username;
            this.password = password;
            this.extra_number = extra_number;
        }//public void SipConnection(string ip, string port, string username, string password, string extra_number = "")

        public string Open()
        {
            Exception exception;

            ipAddress = IPAddress.Parse(this.domain);
            remoteEP = new IPEndPoint(ipAddress, Int32.Parse(this.port));

            try
            {
            sender = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            sender.Connect(remoteEP);
            }
            catch (Exception ex)
            {
            throw new ConnectionFailedException("Unable to connect to the server.  Are your SIP parameters correct?  Is the server available?");
            }

            _newMessage("93");
            _addFixedOption(UIDalgorithm.ToString(), 1);
            _addFixedOption(PWDalgorithm.ToString(), 1);
            _addVarOption("CN", this.username);
            _addVarOption("CO", this.password);
            _addVarOption("CP", scLocation, true);

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string Open()

        public void Close()
        {
            if ((sender != null))
            {
                incrementer = 0;
                sender.Shutdown(SocketShutdown.Both);
                sender.Close();
                connected = false;
            }
            else throw new NotConnectedException("Cannot close connection.  Connection was not established!");
        }//public Close()

        //////PATRON//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        public void setPatron(String Patron)
        {
            this.patron = Patron;
        }//public void setPatron(String Patron)

        public void setPatronpwd(String patronpwd)
        {
            this.patronpwd = patronpwd;
        }//public void setPatronpwd(String patronpwd)

        public string msgBlockPatron(string message, string retained = "N")
        {
            /* Blocks a patron, and responds with a patron status response  (01) - untested */
            _newMessage("01");
            _addFixedOption(retained, 1); /* Y if card has been retained */
            _addFixedOption(_datestamp(), 18);
            _addVarOption("AO", AO);
            _addVarOption("AL", message);
            _addVarOption("AA", patron);
            _addVarOption("AC", AC);

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string msgBlockPatron(string message, string retained= 'N')

        public string msgPatronStatusRequest()
        {
            /* Server Response: Patron Status Response message. */
            _newMessage("23");
            _addFixedOption(language, 3);
            _addFixedOption(_datestamp(), 18);
            _addVarOption("AO", AO);
            _addVarOption("AA", patron);
            _addVarOption("AC", AC);
            _addVarOption("AD", patronpwd);

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string msgPatronStatusRequest()

        public string msgPatronInformation(string type, string start = "1", string end = "5")
        {
            IDictionary<string, string> summary = new Dictionary<string, string>();

            summary["none"] = "          ";
            summary["hold"] = "Y         ";
            summary["overdue"] = " Y        ";
            summary["charged"] = "  Y       ";
            summary["fine"] = "   Y      ";
            summary["recall"] = "    Y     ";
            summary["unavail"] = "     Y    ";
            summary["all"] = "YYYYYY    ";

            /* Request patron information */
            _newMessage("63");
            _addFixedOption(language, 3);
            _addFixedOption(_datestamp(), 18);
            _addFixedOption(summary[type].ToString(), 10);
            _addVarOption("AO", AO);
            _addVarOption("AA", patron);
            _addVarOption("AC", AC, true);
            _addVarOption("AD", patronpwd, true);
            _addVarOption("BP", start, true); /* old function version used padded 5 digits, not sure why */
            _addVarOption("BQ", end, true); /* old function version used padded 5 digits, not sure why */

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string msgPatronInformation(string type, string start = "1", string end = "5")

        public string msgEndPatronSession()
        {
            /*  End Patron Session, should be sent before switching to a new patron. (35) - untested */

            _newMessage("35");
            _addFixedOption(_datestamp(), 18);
            _addVarOption("AO", AO);
            _addVarOption("AA", patron);
            _addVarOption("AC", AC, true);
            _addVarOption("AD", patronpwd, true);

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string msgEndPatronSession()

        public string msgPatronEnable()
        {
            /* Patron Enable public string  (25) - untested */
            /*  This message can be used by the SC to re-enable cancelled patrons. It should only be used for system testing and validation. */
            _newMessage("25");
            _addFixedOption(_datestamp(), 18);
            _addVarOption("AO", AO);
            _addVarOption("AA", patron);
            _addVarOption("AC", AC, true);
            _addVarOption("AD", patronpwd, true);
            return _returnMessage();

        }
        //////ITEM//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        public string msgCheckout(string item, long nbDateDue = 0, string scRenewal = "N", string itmProp = "", string fee = "N", string noBlock = "N", string cancel = "N")
        {
            /* Checkout an item  (11) - untested */
            _newMessage("11");
            _addFixedOption(scRenewal.ToString(), 1);
            _addFixedOption(noBlock.ToString(), 1);
            _addFixedOption(_datestamp(), 18);
            if (nbDateDue != 0)
            {
                /* override default date due */
                _addFixedOption(_datestamp(nbDateDue), 18);
            }
            else
            {
                /* send a blank date due to allow ACS to use default date due computed for item */
                _addFixedOption("                  ", 18);
            }
            _addVarOption("AO", AO);
            _addVarOption("AA", patron);
            _addVarOption("AB", item);
            _addVarOption("AC", AC);
            _addVarOption("CH", itmProp, true);
            _addVarOption("AD", patronpwd, true);
            _addVarOption("BO", fee, true); /* Y or N */
            _addVarOption("BI", cancel, true); /* Y or N */

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public void msgCheckout(string item, string nbDateDue = "", string scRenewal= "N", string itmProp = "", string fee= "N", string noBlock= "N", string cancel= "N")

        public string msgCheckin(string item, long itmReturnDate = 0, string itmLocation = "", string itmProp = "", string noBlock = "N", string cancel = "")
        {
            /* Check-in an item (09) - untested */
            if (itmLocation == "")
            {
                /* If no location is specified, assume the default location of the SC, behaviour suggested by spec*/
                itmLocation = scLocation;
            }

            _newMessage("09");
            _addFixedOption(noBlock.ToString(), 1);
            _addFixedOption(_datestamp().ToString(), 18);
            _addFixedOption(_datestamp(itmReturnDate).ToString(), 18);
            _addVarOption("AP", itmLocation);
            _addVarOption("AO", AO);
            _addVarOption("AB", item);
            _addVarOption("AC", AC);
            _addVarOption("CH", itmProp, true);
            _addVarOption("BI", cancel, true); /* Y or N */

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string msgCheckin(string item, long itmReturnDate=0, string itmLocation = "", string itmProp = "", string noBlock= "N", string cancel = "")

        public string msgSCStatus(int status = 0, string width = " 80", int version = 2)
        {
            /* selfcheck status message, this should be sent immediately after login  - untested */
            /* status codes, from the spec:
                * 0 SC unit is OK
                * 1 SC printer is out of paper
                * 2 SC is about to shut down
                */

            if (version > 3)
            {
                version = 2;
            }
            if (status < 0 || status > 2)
            {
                _debugmsg("SIP2: Invalid status passed to msgSCStatus");
                return "false";
            }
            _newMessage("99");
            _addFixedOption(status.ToString(), 1);
            _addFixedOption(width.ToString(), 3);
            _addFixedOption(version.ToString("N"), 4);

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string  msgSCStatus(int status = 0, int width = 80, int version = 2)

        public string msgFeePaid(int feeType, int pmtType, int pmtAmount, string curType = "USD", string feeId = "", string transId = "")
        {
            /* Fee payment function (37) - untested */
            /* Fee Types: */
            /* 01 other/unknown */
            /* 02 administrative */
            /* 03 damage */
            /* 04 overdue */
            /* 05 processing */
            /* 06 rental*/
            /* 07 replacement */
            /* 08 computer access charge */
            /* 09 hold fee */

            /* Value Payment Type */
            /* 00   cash */
            /* 01   VISA */
            /* 02   credit card */

            if (feeType.GetType() != typeof(int) || feeType > 99 || feeType < 1)
            {
                /* not a valid fee type - exit */
                _debugmsg("SIP2: (msgFeePaid) Invalid fee type: {feeType}");
                return "false";
            }

            if (pmtType.GetType() != typeof(int) || pmtType > 99 || pmtType < 0)
            {
                /* not a valid payment type - exit */
                _debugmsg("SIP2: (msgFeePaid) Invalid payment type: {pmtType}");
                return "false";
            }

            _newMessage("37");
            _addFixedOption(_datestamp(), 18);
            _addFixedOption(feeType.ToString("N"), 2);
            _addFixedOption(pmtType.ToString("N"), 2);
            _addFixedOption(curType, 3);
            _addVarOption("BV", pmtAmount.ToString()); /* due to currency format localization, it is up to the programmer to properly format their payment amount */
            _addVarOption("AO", AO);
            _addVarOption("AA", patron);
            _addVarOption("AC", AC, true);
            _addVarOption("AD", patronpwd, true);
            _addVarOption("CG", feeId, true);
            _addVarOption("BK", transId, true);

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }// public string  msgFeePaid(int feeType, int pmtType, int pmtAmount,string  curType = "USD", string feeId = "", string transId = "")

        public string msgItemInformation(string item)
        {
            _newMessage("17");
            _addFixedOption(_datestamp(), 18);
            _addVarOption("AO", AO);
            _addVarOption("AB", item);
            _addVarOption("AC", AC, true);

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }// public string msgItemInformation(string item)

        public string msgItemStatus(string item, string itmProp = "")
        {
            /* Item status update public string  (19) - untested  */
            _newMessage("19");
            _addFixedOption(_datestamp(), 18);
            _addVarOption("AO", AO);
            _addVarOption("AB", item);
            _addVarOption("AC", AC, true);
            _addVarOption("CH", itmProp);

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string msgItemStatus(string item, string itmProp = "")

        public string msgHold(char mode, long expDate = 0, int holdtype = 0, string item = "", string title = "", string fee = "N", string pkupLocation = "")
        {
            /* mode validity check */
            /* 
            * - remove hold
            * + place hold
            * * modify hold
            */
            string chkMode = "-+*";
            if (chkMode.IndexOf(mode) < 0)
            {
                /* not a valid mode - exit */
                _debugmsg("SIP2: Invalid hold mode: {mode}");
                return "false";
            }

            if (holdtype != 0 && (holdtype < 1 || holdtype > 9))
            {
                /*
                * Valid hold types range from 1 - 9 
                * 1   other
                * 2   any copy of title
                * 3   specific copy
                * 4   any copy at a single branch or location
                */
                _debugmsg("SIP2: Invalid hold type code: {holdtype}");
                return "false";
            }

            _newMessage("15");
            _addFixedOption(mode.ToString(), 1);
            _addFixedOption(_datestamp(), 18);
            if (expDate != 0)
            {
                /* hold expiration date,  due to the use of the datestamp public string , we have to check here for empty value. when datestamp is passed an empty value it will generate a current datestamp */
                _addVarOption("BW", _datestamp(expDate), true); /*spec says this is fixed field, but it behaves like a var field and is optional... */
            }
            _addVarOption("BS", pkupLocation, true);
            _addVarOption("BY", holdtype.ToString(), true);
            _addVarOption("AO", AO);
            _addVarOption("AA", patron);
            _addVarOption("AD", patronpwd, true);
            _addVarOption("AB", item, true);
            _addVarOption("AJ", title, true);
            _addVarOption("AC", AC, true);
            _addVarOption("BO", fee, true); /* Y when user has agreed to a fee notice */

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string msgHold(mode, string expDate = "", string holdtype = "", string item = "", string title = "", string fee= "N", string pkupLocation = "")

        public string msgRenew(string item = "", string title = "", long nbDateDue = 0, string itmProp = "", string fee = "N", string noBlock = "N", string thirdParty = "N")
        {
            /* renew a single item (29) - untested */
            _newMessage("29");
            _addFixedOption(thirdParty, 1);
            _addFixedOption(noBlock, 1);
            _addFixedOption(_datestamp(), 18);
            if (nbDateDue > 0)
            {
                /* override default date due */
                _addFixedOption(_datestamp(nbDateDue), 18);
            }
            else
            {
                /* send a blank date due to allow ACS to use default date due computed for item */
                _addFixedOption("", 18);
            }
            _addVarOption("AO", AO);
            _addVarOption("AA", patron);
            _addVarOption("AD", patronpwd, true);
            _addVarOption("AB", item, true);
            _addVarOption("AJ", title, true);
            _addVarOption("AC", AC, true);
            _addVarOption("CH", itmProp, true);
            _addVarOption("BO", fee, true); /* Y or N */

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string msgRenew(string item = "", string title = "", long nbDateDue = 0 , string itmProp = "", string fee= "N", string noBlock = "N", string thirdParty = "N")

        public string msgRenewAll(string fee = "N")
        {
            /* renew all items for a patron (65) - untested */
            _newMessage("65");
            _addVarOption("AO", AO);
            _addVarOption("AA", patron);
            _addVarOption("AD", patronpwd, true);
            _addVarOption("AC", AC, true);
            _addVarOption("BO", fee, true); /* Y or N */

            string sipCommand = string.Format(_returnMessage());
            return _sendCommand(sipCommand);
        }//public string msgRenewAll(string fee = "N")

        public IDictionary<string, IDictionary<string, string>> parsePatronStatusResponse(string response)
        {

            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["PatronStatus"] = response.Substring(2, 14);
            result1["Language"] = response.Substring(16, 3);
            result1["TransactionDate"] = response.Substring(19, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 37);
            return result;
        }//public IDictionary<string, IDictionary<string, string>> parsePatronStatusResponse(string response)

        //////parse---Response//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        public IDictionary<string, IDictionary<string, string>> parseCheckoutResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();
            result1["Ok"] = response.Substring(2, 1);
            result1["RenewalOk"] = response.Substring(3, 1);
            result1["Magnetic"] = response.Substring(4, 1);
            result1["Desensitize"] = response.Substring(5, 1);
            result1["OTransactionDatek"] = response.Substring(6, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 24);
            return result;
        }//public IDictionary<string, IDictionary<string, string>> parseCheckoutResponse(string response)

        public IDictionary<string, IDictionary<string, string>> parseCheckinResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();
            result1["Ok"] = response.Substring(2, 1);
            result1["Resensitize"] = response.Substring(3, 1);
            result1["Magnetic"] = response.Substring(4, 1);
            result1["Alert"] = response.Substring(5, 1);
            result1["TransactionDate"] = response.Substring(6, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 24);
            return result;
        }

        public IDictionary<string, IDictionary<string, string>> parseACSStatusResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["Online"] = response.Substring(2, 1);
            result1["Checkin"] = response.Substring(3, 1);
            result1["Checkout"] = response.Substring(4, 1);
            result1["Renewal"] = response.Substring(5, 1);
            result1["PatronUpdate"] = response.Substring(6, 18);
            result1["Offline"] = response.Substring(7, 1);
            result1["Timeout"] = response.Substring(8, 3);
            result1["Retries"] = response.Substring(11, 3);
            result1["TransactionDate"] = response.Substring(14, 18);
            result1["Protocol"] = response.Substring(32, 4);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 36);
            return result;
        }//public IDictionary<string, IDictionary<string, string>>  parseACSStatusResponse(string response)

        public IDictionary<string, IDictionary<string, string>> parseLoginResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["Ok"] = response.Substring(2, 1);

            result["fixed"] = result1;
            result["variable"] = result1;
            return result;
        }//public IDictionary<string, IDictionary<string, string>> parseLoginResponse(string response)

        public IDictionary<string, IDictionary<string, string>> parsePatronInfoResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["PatronStatus"] = response.Substring(2, 14);
            result1["Language"] = response.Substring(16, 3);
            result1["TransactionDate"] = response.Substring(19, 18);
            result1["HoldCount"] = response.Substring(37, 4);
            result1["OverdueCount"] = response.Substring(41, 4);
            result1["ChargedCount"] = response.Substring(45, 4);
            result1["FineCount"] = response.Substring(49, 4);
            result1["RecallCount"] = response.Substring(53, 4);
            result1["UnavailableCount"] = response.Substring(57, 4);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 61);
            return result;
        }//IDictionary<string, IDictionary<string, string>>

        public IDictionary<string, IDictionary<string, string>> parseEndSessionResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["EndSession"] = response.Substring(2, 1);
            result1["TransactionDate"] = response.Substring(3, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 21);
            return result;
        }//public IDictionary<string, IDictionary<string, string>> parseEndSessionResponse(string response)

        public IDictionary<string, IDictionary<string, string>> parseFeePaidResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["PaymentAccepted"] = response.Substring(2, 1);
            result1["TransactionDate"] = response.Substring(3, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 21);
            return result;

        }//public IDictionary<string, IDictionary<string, string>> parseFeePaidResponse(string response)

        public IDictionary<string, IDictionary<string, string>> parseItemInfoResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["CirculationStatus"] = response.Substring(2, 2);
            result1["SecurityMarker"] = response.Substring(4, 2);
            result1["FeeType"] = response.Substring(6, 2);
            result1["TransactionDate"] = response.Substring(8, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 26);
            return result;
        }//public IDictionary<string, IDictionary<string, string>> parseItemInfoResponse(string response)

        public IDictionary<string, IDictionary<string, string>> parseItemStatusResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["PropertiesOk"] = response.Substring(2, 1);
            result1["TransactionDate"] = response.Substring(3, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 21);
            return result;

        }//public IDictionary<string, IDictionary<string, string>> parseItemStatusResponse(string response)

        public IDictionary<string, IDictionary<string, string>> parsePatronEnableResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["PatronStatus"] = response.Substring(2, 14);
            result1["Language"] = response.Substring(16, 3);
            result1["TransactionDate"] = response.Substring(19, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 37);
            return result;
        }//public IDictionary<string, IDictionary<string, string>> parsePatronEnableResponse(string response)

        public IDictionary<string, IDictionary<string, string>> parseHoldResponse(string response)
        {

            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["Ok"] = response.Substring(2, 1);
            result1["available"] = response.Substring(3, 1);
            result1["TransactionDate"] = response.Substring(4, 18);
            result1["ExpirationDate"] = response.Substring(2, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 40);
            return result;
        }//public IDictionary<string, IDictionary<string, string>> parseHoldResponse(string response)

        public IDictionary<string, IDictionary<string, string>> parseRenewResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["Ok"] = response.Substring(2, 1);
            result1["RenewalOk"] = response.Substring(3, 1);
            result1["Magnetic"] = response.Substring(4, 1);
            result1["Desensitize"] = response.Substring(5, 1);
            result1["TransactionDate"] = response.Substring(6, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 24);
            return result;
        }//public IDictionary<string, IDictionary<string, string>> parseRenewResponse(string response)

        public IDictionary<string, IDictionary<string, string>> parseRenewAllResponse(string response)
        {
            IDictionary<string, IDictionary<string, string>> result = new Dictionary<string, IDictionary<string, string>>();
            IDictionary<string, string> result1 = new Dictionary<string, string>();

            result1["Ok"] = response.Substring(2, 1);
            result1["Renewed"] = response.Substring(3, 4);
            result1["Unrenewed"] = response.Substring(7, 4);
            result1["TransactionDate"] = response.Substring(11, 18);

            result["fixed"] = result1;
            result["variable"] = _parsevariabledata(response, 29);
            return result;
        }

        //////PRIVATE/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        private IDictionary<string, string> _parsevariabledata(string response, int start)
        {
            string field;
            string value;
            string clean;
            int len = response.Length - start - 7;
            IDictionary<string, string> result = new Dictionary<string, string>();
            string[] Raw = response.Substring(start, len).Split('|');
            //result["Raw"] =
            char[] charsToTrim = {
                    '\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07'
                    , '\x08', '\x09', '\x0a', '\x0b', '\x0c','\x0d','\x0e','\x0f'
                    ,'\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17'
                    , '\x18', '\x19', '\x1a', '\x1b', '\x1c','\x1d','\x1e','\x1f'};

            foreach (string item in Raw)
            {
                field = item.Substring(0, 2);
                value = item.Substring(2); //substr(item, 2);
                /* SD returns some odd values on occasion, Unable to locate the purpose in spec, so I strip from 
                * the parsed array. Orig values will remain in ["raw"] element
                */
                clean = value.Trim(charsToTrim);//trim(value, "\x00..\x1F");
                if (clean.Trim() != "")
                {
                    result[field] = "";
                }
            }

            foreach (string item in Raw)
            {
                field = item.Substring(0, 2);
                value = item.Substring(2); //substr(item, 2);
                /* SD returns some odd values on occasion, Unable to locate the purpose in spec, so I strip from 
                * the parsed array. Orig values will remain in ["raw"] element
                */
                clean = value.Trim(charsToTrim);//trim(value, "\x00..\x1F");
                if (clean.Trim() != "")
                {
                    if (string.IsNullOrEmpty(result[field]))
                    {
                        result[field] = clean;
                    }
                    else
                    {
                        result[field] += "|" + clean;
                    }

                }
            }
            len = response.Length - 5;
            result["AZ"] = response.Substring(len);

            return (result);
        }

        private int _getseqnum()
        {
            /* Get a sequence number for the AY field */
            /* valid numbers range 0-9 */
            seq++;
            if (seq > 9)
            {
                seq = 0;
            }
            return seq;
        }//private _getseqnum()


        private string _datestamp(long timestamp = 0)
        {
            /* generate a SIP2 compatible datestamp */
            /* From the spec:
            * YYYYMMDDZZZZHHMMSS. 
            * All dates and times are expressed according to the ANSI standard X3.30 for date and X3.43 for time. 
            * The ZZZZ field should contain blanks (code $20) to represent local time. To represent universal time, 
            *  a Z character(code $5A) should be put in the last (right hand) position of the ZZZZ field. 
            * To represent other time zones the appropriate character should be used; a Q character (code $51) 
            * should be put in the last (right hand) position of the ZZZZ field to represent Atlantic Standard Time. 
            * When possible local time is the preferred format.
            */

            DateTime aDate;
            if (timestamp != 0)
            {
                aDate = new DateTime(timestamp);
            }
            else
            {
                aDate = DateTime.Now;
            }


            return aDate.ToString("yyyyMMdd    HHmmss", new CultureInfo("en-US"));
        }//private _datestamp($timestamp = '')


        private string _crc(string buf)
        {
            /* Calculate CRC  */
            int sum = 0;

            string finalValue;
            byte[] ascii = Encoding.ASCII.GetBytes(buf);
            foreach (Byte b in ascii)
            {
                sum += b;
            }

            sum = sum * (-1);
            return sum.ToString("X").Substring(4, 4);
        }//private _crc($buf)

        private void _debugmsg(string message)
        {
            /* custom debug function,  why repeat the check for the debug flag in code... */
            if (debug)
            {
                //trigger_error( message, E_USER_NOTICE);
            }
        }//private _debugmsg($message)

        //        private _check_crc($message)
        //        {
        //        /* test the received message's CRC by generating our own CRC from the message */
        //        $test = preg_split('/(.{4})$/', trim($message), 2, PREG_SPLIT_DELIM_CAPTURE);

        //            if (crc($test[0]) == $test[1]) {
        //                return true;
        //            } else
        //            {
        //                return false;
        //            }
        //        }//private _check_crc($message)

        private void _newMessage(string code)
        {
            /* resets the msgBuild variable to the value of $code, and clears the flag for fixed messages */
            noFixed = false;
            msgBuild = code;
        }//private _newMessage($code)

        private bool _addFixedOption(string value, int len)
        {
            /* adds a fixed length option to the msgBuild IF no variable options have been added. */
            if (noFixed)
            {
                return false;
            }
            else
            {
                msgBuild += value.Substring(0, len);
                return true;
            }
        }//private_addFixedOption($value, $len)

        private bool _addVarOption(string field, string value, bool optional = false)
        {
            /* adds a variable length option to the message, and also prevents adding additional fixed fields */
            if (optional == true && value == "")
            {
                /* skipped */
                _debugmsg("SIP2: Skipping optional field {$field}");
            }
            else
            {
                noFixed = true; /* no more fixed for this message */
                msgBuild += field + value + fldTerminator;
            }
            return true;
        }//private _addVarOption($field, $value, $optional = false)


        private string _returnMessage(bool withSeq = true, bool withCrc = true)
        {
            /* Finalizes the message and returns it.  Message will remain in msgBuild until newMessage is called */
            if (withSeq)
            {
                msgBuild += "AY" + _getseqnum().ToString();
            }
            if (withCrc)
            {
                msgBuild += "AZ";
                msgBuild += _crc(msgBuild);
            }
            msgBuild += msgTerminator;

            return msgBuild;
        }//private _returnMessage($withSeq = true, $withCrc = true)

        private string _sendCommand(string sipCommand)
        {
            byte[] bytes = new byte[8192];
            byte[] msg = Encoding.ASCII.GetBytes(sipCommand + '\r');
            int bytesSent = sender.Send(msg);
            //StringBuilder outputString = new StringBuilder();
            string bit = String.Empty;
            while (!bit.Contains("\r"))
            {
                sender.Receive(bytes);
                bit = Encoding.ASCII.GetString(bytes);
                //for (int i = 0; i <= bit.Length - 1; i++)
                //{
                //    if (bit[i] == '\r') { break; }
                //    if (bit[i] != '\0') { outputString.Append(bit[i]); }
                //}
            }

            //MessageBox.Show(outputString.ToString());
            //return outputString.ToString();
            return System.Text.Encoding.UTF8.GetString(bytes);
        }//private string _sendCommand(string sipCommand)

        public void Dispose()
        {
            throw new NotImplementedException();
        }//public void Dispose()
    }
}
