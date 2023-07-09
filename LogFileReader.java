import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInput;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.Properties;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

import org.apache.derby.iapi.services.crypto.CipherFactory;
import org.apache.derby.iapi.services.crypto.CipherProvider;
import org.apache.derby.iapi.services.io.CompressedNumber;
import org.apache.derby.iapi.services.io.FormatIdInputStream;
import org.apache.derby.iapi.services.io.FormatIdUtil;
import org.apache.derby.iapi.services.io.RegisteredFormatIds;
import org.apache.derby.iapi.services.io.StoredFormatIds;
import org.apache.derby.iapi.store.raw.Loggable;
import org.apache.derby.shared.common.reference.Attribute;
import org.apache.derby.impl.services.jce.JCECipherFactoryBuilder;

/**
 * Utility to read a log file in the log directory of a
 * Derby database. This is based on the 10.8 version of
 * log records handled by LogToFile.
 */
public  class   LogFileReader
{
    ////////////////////////////////////////////////////////////////////////
    //
    //  CONSTANTS
    //
    ////////////////////////////////////////////////////////////////////////

    private static  final   String  USAGE =
        "Usage:\n" +
        "\n" +
        "    java LogFileReader $logFileName [ -v ] [ -p $P ] [ -n $N ] [ -e $bootPassword $serviceProperties ]\n" +
        "\n" +
        "    -v   Verbose. Deserialize the logged operations. If you do not set this flag, the tool just decodes the wrapper headers.\n" +
        "    -p   Starting position. $P is a positive number, the offset of the first log entry to read. This causes the tool to skip reading the file header as well.\n" +
        "    -n   Number of records to read. $N is a non-negative number. If you do not specify this flag, the tool prints all subsequent log entries.\n" +
        "    -e   If the database is encrypted, you must supply the boot password and the location of service.properties.\n";
    
    // enough bytes for RecordFormatID + GroupFlags + TransactionID + OperationFormatID
    private static  final   int MINIMUM_RECORD_HEADER_LENGTH = 18;

    private static  final   int READ_ALL_RECORDS = -1;
        
    ////////////////////////////////////////////////////////////////////////
    //
    //  STATE
    //
    ////////////////////////////////////////////////////////////////////////

    public  static  final   DevNull devNull = new DevNull();

    //
    // Args.
    //
    private static  String  _logFileName;
    private static  boolean _verbose;
    private static  int         _startPosition = 0;
    private static  int         _maxRecordCount = READ_ALL_RECORDS;
    private static  CipherProvider  _decryptionEngine;
    
    ////////////////////////////////////////////////////////////////////////
    //
    //  ENTRY POINT
    //
    ////////////////////////////////////////////////////////////////////////
    
    public  static  void    main( String... args )  throws Exception
    {
        if ( !parseArgs( args ) ) { usage(); }

        LogFile logFile = new LogFile( new File( _logFileName ), _verbose, _startPosition, _maxRecordCount, _decryptionEngine );

        logFile.printMe( System.out );
    }
    private static  boolean parseArgs( String... args )
    {
        if ( (args == null) || (args.length < 1) ) { return false; }

        int argCount = args.length;
        int idx = 0;

        _logFileName = args[ idx++ ];

        // optional args
        while ( idx < argCount )
        {
            String  arg = args[ idx++ ];

            if ( "-v".equals( arg )  ) { _verbose = true; }
            else if ( "-p".equals( arg ) )
            {
                if ( idx >= argCount ) { return false; }
                try {
                    _startPosition = Integer.parseInt( args[ idx++ ] );
                    if ( _startPosition < 0 ) { return false; }
                }
                catch (Exception e) { return false; }
            }
            else if ( "-n".equals( arg ) )
            {
                if ( idx >= argCount ) { return false; }
                try {
                    _maxRecordCount = Integer.parseInt( args[ idx++ ] );
                    if ( _maxRecordCount < 0 ) { return false; }
                }
                catch (Exception e) { return false; }
            }
            else if ( "-e".equals( arg ) )
            {
                if ( idx + 1 >= argCount ) { return false; }

                String  bootPassword = args[ idx++ ];
                File    serviceProperties = new File( args[ idx++ ] );
                try {
                    _decryptionEngine = makeDecryptionEngine( bootPassword, serviceProperties );
                }
                catch (Exception e)
                {
                    System.out.println( e.getMessage() );
                    return false;
                }
            }
            else { return false; }
        }

        return true;
    }
    private static  void    usage()
    {
        System.out.println( USAGE );
        System.exit( 1 );
    }
    private static  CipherProvider  makeDecryptionEngine
        ( String bootPassword, File serviceProperties ) throws Exception
    {
        Properties  properties = new Properties();
        properties.load( new FileInputStream( serviceProperties ) );

        properties.setProperty( Attribute.BOOT_PASSWORD, bootPassword );

        CipherFactory    cipherFactory =
            new JCECipherFactoryBuilder()
            .createCipherFactory( false, properties, false );

        return cipherFactory.createNewCipher( CipherFactory.DECRYPT );
    }
    
    private static  void    skipBytes( DataInputStream dais, int bytesToSkip ) throws IOException
    {
        int     actualBytesSkipped = dais.skipBytes( bytesToSkip );

        if ( actualBytesSkipped != bytesToSkip )
        {
            throw new IOException( "Expected to skip " + bytesToSkip + " bytes but only skipped " + actualBytesSkipped + " bytes." );
        }
    }

    ////////////////////////////////////////////////////////////////////////
    //
    //  NESTED CLASSES
    //
    ////////////////////////////////////////////////////////////////////////

    public  static  final   class   LogFile
    {
        // constructor args
        
        private File            _file;
        private boolean     _readWholeRecord;
        private int             _startPosition;
        private int             _maxRecordCount;
        private CipherProvider  _decryptionEngine;
        
        // control fields

        private int             _recordCount;
        private Throwable   _error;

        
        public  LogFile( File file, boolean readWholeRecord, int startPosition, int maxRecordCount, CipherProvider decryptionEngine )    throws Exception
        {
            _file = file;
            _readWholeRecord = readWholeRecord;
            _startPosition = startPosition;
            _maxRecordCount = maxRecordCount;
            _decryptionEngine = decryptionEngine;
        }

        public  void    printMe( PrintStream printStream )  throws Exception
        {
            _recordCount = 0;

            XMLWriter   ps = new XMLWriter( printStream );
            
            ps.println( "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>" );

            ps.beginTag( "logFile" );
            {
                FileInputStream fis = new FileInputStream( _file );
                DataInputStream dais = new DataInputStream( fis );

                if ( _readWholeRecord )
                {
                    //
                    // We need a Monitor in order to use the formatable machinery to decode
                    // record contents.
                    //
                    // Redirect error log to the bit bucket so that we don't trample derby.log.
                    //
                    System.setProperty( "derby.stream.error.field", "LogFileReader.devNull" );
                    Class.forName(  "org.apache.derby.jdbc.EmbeddedDriver" );
                    Connection  conn = DriverManager.getConnection( "jdbc:derby:memory:db;create=true" );
                }

                readFile( dais, ps );
                
                if ( _error != null )
                {
                    formatError( ps );
                }

                dais.close();
                fis.close();
            }
            ps.endTag();   // logFile
        }

        private void    readFile( DataInputStream dais, XMLWriter ps )
        {
            try {
                if ( _startPosition > 0 )   { skipBytes( dais, _startPosition ); }
                else { readFileHeader( ps, dais ); }
                
                ps.beginTag( "logRecords" );
                {
                    readLogRecords( ps, dais );
                }
                ps.endTag();   // logRecords
                
                createTextElement( ps, "recordCount", Integer.toString( _recordCount ) );
                
            } catch (Throwable t)
            {
                _error = t;
            }
        }
        private void    readFileHeader( XMLWriter ps, DataInputStream dais ) throws Exception
        {
            int     formatableID = dais.readInt();
            //int     formatableID = 128;
            if ( formatableID != StoredFormatIds.FILE_STREAM_LOG_FILE )
            {
                new IOException
                    (
                     "File header should start with formatable id " + StoredFormatIds.FILE_STREAM_LOG_FILE +
                     " but instead starts with formatable id " + formatableID
                     );
            }
            createIntElement( ps, "formatableID", formatableID );

            int     obsoleteVersion = dais.readInt();
            createIntElement( ps, "obsoleteVersion", obsoleteVersion );

            long    logFileNumber = dais.readLong();
            createLongElement( ps, "logFileNumber", logFileNumber );

            long    previousLogRecordEndInstant = dais.readLong();
            formatLogCounter( ps, previousLogRecordEndInstant, "previousLogRecordEndInstant" );
        }

        private void    readLogRecords( XMLWriter ps, DataInputStream dais )  throws Exception
        {
            while ( true )
            {
                if (
                    (_maxRecordCount != READ_ALL_RECORDS) &&
                    (_recordCount >= _maxRecordCount)
                    )
                { break; }
                
                LogRecordWrapper    nextWrapper = new LogRecordWrapper( dais, _readWholeRecord, _decryptionEngine );

                if ( nextWrapper.getLogRecordLengthForward() <= 0 ) { break; }

                _recordCount++;
                formatWrapper( ps, nextWrapper );
            }
        }

        private void formatError( XMLWriter ps ) throws Exception
        {
            StringWriter    sw = new StringWriter();
            PrintWriter     pw = new PrintWriter( sw );

            _error.printStackTrace( pw );
            pw.flush();

            createTextElement( ps, "message", _error.getClass().getName() + ": " + _error.getMessage() );
            createTextElement( ps, "stackTrace", sw.toString() );
        }

        private void    formatWrapper( XMLWriter ps, LogRecordWrapper recordWrapper )   throws Exception
        {
            ps.beginTag( "wrapper" );
            {
                createIntElement( ps, "forwardLength", recordWrapper.getLogRecordLengthForward());
                formatLogCounter( ps, recordWrapper.getLogInstant(), "logInstant" );
                formatLogRecord( ps, recordWrapper.getLogRecord() );
                createIntElement( ps, "backwardLength", recordWrapper.getLogRecordLengthBackward() );
            }
            ps.endTag();   // wrapper
        }
        
        private void formatLogRecord( XMLWriter ps, byte[] logRecord )   throws Exception
        {
            ps.beginTag( "logRecord" );
            {
                if ( logRecord != null )
                {
                    ByteArrayInputStream    bais = new ByteArrayInputStream( logRecord );
                    DataInputStream         dais = new DataInputStream( bais );

                    int     formatableID = FormatIdUtil.readFormatIdInteger( dais );
                    createIntElement( ps, "formatableID", formatableID );
                    if ( formatableID != StoredFormatIds.LOG_RECORD )
                    {
                        //throw new IOException( "Expected to see a log record id, but instead read formatable id " + formatableID );
                    }
                    
                    int     groups = 0;
                    try {groups = CompressedNumber.readInt( (DataInput) dais );} catch (Exception e) {}
                    
                    formatLogGroups( ps, groups );

                    formatTransactionID( ps, dais );
                    formatOperation( ps, dais );
                }
            }
            ps.endTag();   // logRecord
        }

        private void formatOperation( XMLWriter ps, DataInputStream dais )
            throws Exception
        {
            if ( _readWholeRecord ) { formatWholeOperation( ps, dais ); }
            else { formatOperationHeader( ps, dais ); }
        }

        // for verbose printout
        private void formatWholeOperation( XMLWriter ps, DataInputStream dais )
            throws Exception
        {
            FormatIdInputStream fiis = new FormatIdInputStream( dais );
            Object                  operation = null;
            try {operation = fiis.readObject();} catch (Exception e) {}
            

            String      operationName = (operation == null) ? "NULL" : operation.getClass().getName();

            ps.beginTag( "operation", "type=" + doubleQuote( operationName ) );
            {
            	try {createTextElement( ps, "details", operation.toString() );} catch (Exception e) {}  
            }
            ps.endTag();   // operation
        }

        // for short printout
        private void formatOperationHeader( XMLWriter ps, DataInputStream dais )
            throws Exception
        {
            int     formatableID = 0;
            try {formatableID = FormatIdUtil.readFormatIdInteger( dais );} catch (Exception e) {}

            String      operationName = null;
            try {operationName = RegisteredFormatIds.TwoByte[ formatableID ];} catch (Exception e) {}

            ps.writeEmptyTag( "operation", "type=" + doubleQuote( operationName ) );
        }
        
        private void formatTransactionID( XMLWriter ps, DataInputStream dais )
            throws Exception
        {
            int     formatableID = 0;
            try {formatableID = FormatIdUtil.readFormatIdInteger( dais );} catch (Exception e) {}
            

            if ( (formatableID != StoredFormatIds.RAW_STORE_XACT_ID) && (formatableID != StoredFormatIds.NULL_FORMAT_ID) )
            {
                //throw new IOException( "Expected to see a transaction id, but instead read formatable id " + formatableID );
            }
            
            String    transactionNumber = (formatableID == StoredFormatIds.NULL_FORMAT_ID) ?
                "NULL" : Long.toString( CompressedNumber.readLong( (DataInput) dais ) );

            ps.writeEmptyTag( "transactionID", "value=" + doubleQuote( transactionNumber ) );
        }
        private void formatLogGroups( XMLWriter ps, int groups ) throws Exception
        {
            ps.beginTag( "groups", "hexvalue=" + doubleQuote( Integer.toHexString( groups ) ) );
            {
                String  flag = "flag";

                if ( (groups & Loggable.FIRST) != 0 )
                {
                    createTextElement( ps, flag, "FIRST" );
                }
                if ( (groups & Loggable.LAST) != 0 )
                {
                    createTextElement( ps, flag, "LAST" );
                }
                if ( (groups & Loggable.COMPENSATION) != 0 )
                {
                    createTextElement( ps, flag, "COMPENSATION" );
                }
                if ( (groups & Loggable.BI_LOG) != 0 )
                {
                    createTextElement( ps, flag, "BI_LOG" );
                }
                if ( (groups & Loggable.COMMIT) != 0 )
                {
                    createTextElement( ps, flag, "COMMIT" );
                }
                if ( (groups & Loggable.ABORT) != 0 )
                {
                    createTextElement( ps, flag, "ABORT" );
                }
                if ( (groups & Loggable.PREPARE) != 0 )
                {
                    createTextElement( ps, flag, "PREPARE" );
                }
                if ( (groups & Loggable.XA_NEEDLOCK) != 0 )
                {
                    createTextElement( ps, flag, "XA_NEEDLOCK" );
                }
                if ( (groups & Loggable.RAWSTORE) != 0 )
                {
                    createTextElement( ps, flag, "RAWSTORE" );
                }
                if ( (groups & Loggable.FILE_RESOURCE) != 0 )
                {
                    createTextElement( ps, flag, "FILE_RESOURCE" );
                }
                if ( (groups & Loggable.CHECKSUM) != 0 )
                {
                    createTextElement( ps, flag, "CHECKSUM" );
                }
            }
            ps.endTag();   // groups
        }

        
        private void formatLogCounter( XMLWriter ps, long logCounter, String tag )
            throws Exception
        {
            ps.beginTag( tag );
            {
                int     logFileNumber = (int) (logCounter >>> 32);
                createIntElement( ps, "logFileNumber", logFileNumber );

                int     position = (int) (0xFFFFFFFF & logCounter);
                createIntElement( ps, "position", position );
            }
            ps.endTag();
        }
        private void createLongElement( XMLWriter ps, String tag, long value )
            throws Exception
        {
            createTextElement( ps, tag, Long.toString( value ) );
        }
        private void createIntElement( XMLWriter ps, String tag, int value )
            throws Exception
        {
            createTextElement( ps, tag, Integer.toString( value ) );
        }
        private void    createTextElement( XMLWriter ps, String tag, String text )
            throws Exception
        {
            ps.writeTextElement( tag, text );
        }

        private String  doubleQuote( String text )
        {
            return "\"" + text + "\"";
        }

    }
    
    public  static  final   class   LogRecordWrapper
    {
        private int     _logRecordLengthForward;
        private long    _logInstant;
        private byte[]   _logRecord;
        private int     _logRecordLengthBackward;
        
        public  int getLogRecordLengthForward() { return _logRecordLengthForward; }
        private long    getLogInstant() { return _logInstant; }
        private byte[]   getLogRecord() { return _logRecord; }
        private int     getLogRecordLengthBackward() { return _logRecordLengthBackward; }

        public  LogRecordWrapper( DataInputStream dais, boolean readWholeRecord, CipherProvider decryptionEngine )    throws Exception
        {
            try {
                _logRecordLengthForward = dais.readInt();
            } catch (EOFException eof) { return ; }

            if ( _logRecordLengthForward == 0 ) { return; }

            _logInstant = dais.readLong();
            _logRecord = readRecord( dais, decryptionEngine );
            try {_logRecordLengthBackward = dais.readInt();} catch (Exception e) {}
            

            if ( _logRecordLengthForward != _logRecordLengthBackward )
            {
                //throw new IOException
                   // ( "Not positioned on a legal log entry. Forward length " + _logRecordLengthForward + " differs from backward length " + _logRecordLengthBackward );
            }
        }

        private byte[] readRecord( DataInputStream dais, CipherProvider decryptionEngine  )
            throws Exception
        {
            int realLength = _logRecordLengthForward;
            int tail = 0;
            int padding = 0;

            if ( decryptionEngine != null )
            {
                tail = realLength % decryptionEngine.getEncryptionBlockSize();
                padding = (tail == 0) ? 0 : (decryptionEngine.getEncryptionBlockSize() - tail);
            }

            int encryptedLength = realLength + padding;
            encryptedLength = encryptedLength > 0 ? encryptedLength : 0;
            
            byte[]  record = new byte[ encryptedLength ];
            
            //if ( record !=  null ) { dais.readFully( record );} 
            try {dais.readFully( record );} catch (Exception e) {}
            
            

            record = decrypt( decryptionEngine, record, padding, realLength );

            return record;
        }
        private byte[]  decrypt( CipherProvider decryptionEngine, byte[] cipherText, int padding, int realLength )
            throws Exception
        {
            if ( decryptionEngine ==  null ) { return cipherText; }

            int     encryptedLength = cipherText.length;
            byte[]  clearText = new byte[ encryptedLength ];

            decryptionEngine.decrypt( cipherText, 0, encryptedLength, clearText, 0 );

            byte[]  result = new byte[ realLength ];
            System.arraycopy( clearText, padding, result, 0, realLength );

            return result;
        }

    }

    ////////////////////////////////////////////////////////////////////////
    //
    // MACHINE FOR STREAMING XML TO SYSTEM OUT
    //
    ////////////////////////////////////////////////////////////////////////
    
    /**
     * <p>
     * XML-writing wrapper around a PrintStream.
     * </p>
     */
    public  static  final   class   XMLWriter
    {
        private static  final   String  TAB_STOP = "    ";
    
        // If this boolean is set, then all operations are NOPs.
        private         boolean       _vacuous;
        
        private         PrintStream _pw;
        private         ArrayList<String>    _tagStack;

        /**
         * <p>
         * Special constructor for making a vacuous writer which doesn't do
         * anything. This allows us to write easy-to-read dita-generating code
         * that is not cluttered with "if ( documented )" conditionals.
         * </p>
         */
        public  XMLWriter()
        {
            _vacuous = true;
         }

        /**
         * <p>
         * Create a productive writer which actually flushes text to a PrintStream.
         * </p>
         */
        public  XMLWriter( PrintStream printStream )
            throws IOException
        {
            _vacuous = false;
            _pw = printStream;
            _tagStack = new ArrayList<String>();
        }

        public  void    flush() throws IOException
        {
            if ( _vacuous ) { return; }
            
            _pw.flush();
        }
        
        public  void    close() throws IOException
        {
        }

        /**
         * <p>
         * Indent and write an empty tag.
         * </p>
         */
        public void    writeEmptyTag( String tag )
            throws IOException
        {
            if ( _vacuous ) { return; }

            writeEmptyTag( tag, "" );
        }

        /**
         * <p>
         * Indent and write an empty tag with attributes.
         * </p>
         */
        public void    writeEmptyTag( String tag, String attributes )
            throws IOException
        {
            if ( _vacuous ) { return; }

            indent( );
            if ( attributes.length() >0)
                _pw.println( "<" + tag + " " + attributes + "/>");
            else
                _pw.println( "<" + tag + "/>");
        }

        /**
         * <p>
         * Indent and write an opening tag.
         * </p>
         */
        public void    beginTag( String tag )
            throws IOException
        {
            if ( _vacuous ) { return; }

            beginTag( tag, "" );
        }

        /**
         * <p>
         * Indent and write an opening tag.
         * </p>
         */
        public void    beginTag( String tag, String attributes )
            throws IOException
        {
            if ( _vacuous ) { return; }

            indent();
            if (attributes.length() > 0)
                _pw.println( "<" + tag + " " + attributes + ">");
            else
                _pw.println( "<" + tag + ">");

            _tagStack.add( tag );
        }

        /**
         * <p>
         * Indent and write a closing tag.
         * </p>
         */
        public void    endTag()
            throws IOException
        {
            if ( _vacuous ) { return; }

            String  tag = (String) _tagStack.remove( _tagStack.size() -1 );
        
            indent();

            _pw.println( "</" + tag + ">");
        }

        /**
         * <p>
         * Indent and write a whole element
         * </p>
         */
        public void    writeTextElement( String tag, String text )
            throws IOException
        {
            if ( _vacuous ) { return; }

            writeTextElement( tag, "", text );
        }

        /**
         * <p>
         * Indent and write a whole element
         * </p>
         */
        public void    writeTextElement( String tag, String attributes, String text )
            throws IOException
        {
            if ( _vacuous ) { return; }

            indent();
            if ( attributes.length() > 0 )
                _pw.print( "<" + tag + " " + attributes + ">");
            else
                _pw.print( "<" + tag + ">");
            _pw.print( text );
            _pw.println( "</" + tag + ">");
        }

        /**
         * <p>
         * Indent based on the depth of our tag nesting level.
         * </p>
         */
        public void    indent()
            throws IOException
        {
            if ( _vacuous ) { return; }

            int     tabCount = _tagStack.size();

            for ( int i = 0; i < tabCount; i++ ) { _pw.print( TAB_STOP ); }
        }

                /**
         * <p>
         * Print text.
         * </p>
         */
        public void    println( String text )
            throws IOException
        {
            if ( _vacuous ) { return; }

            _pw.println( text );
        }

    }
    
    ////////////////////////////////////////////////////////////////////////
    //
    // /dev/null
    //
    ////////////////////////////////////////////////////////////////////////

    public  static  final   class   DevNull extends OutputStream { public  void    write( int b ) {} }
    
}
