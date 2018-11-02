#coding=utf-8
from burp import IBurpExtender
from burp import ITab
from burp import IHttpListener
from burp import IMessageEditorController
from java.awt import Component;
from java.io import PrintWriter;
from java.util import ArrayList;
from java.util import List;
from javax.swing import JScrollPane;
from javax.swing import JSplitPane;
from javax.swing import JTabbedPane;
from javax.swing import JTable;
from javax.swing import SwingUtilities;
from javax.swing.table import AbstractTableModel;
from threading import Lock
import re

class BurpExtender(IBurpExtender, ITab, IHttpListener, IMessageEditorController, AbstractTableModel):    
    #
    # implement IBurpExtender
    #
    def	registerExtenderCallbacks(self, callbacks):
        # keep a reference to our callbacks object
        self._callbacks = callbacks
        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()
        # set our extension name
        callbacks.setExtensionName("sensitive")
        # create the log and a lock on which to synchronize when adding log entries
        self._log = ArrayList()
        self._lock = Lock()
        # main split pane
        self._splitpane = JSplitPane(JSplitPane.VERTICAL_SPLIT)
        # table of log entries
        logTable = Table(self)
        scrollPane = JScrollPane(logTable)
        self._splitpane.setLeftComponent(scrollPane)
        # tabs with request/response viewers
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor(self, False)
        self._responseViewer = callbacks.createMessageEditor(self, False)
        tabs.addTab("Request", self._requestViewer.getComponent())
        tabs.addTab("Response", self._responseViewer.getComponent())
        self._splitpane.setRightComponent(tabs)        
        # customize our UI components
        callbacks.customizeUiComponent(self._splitpane)
        callbacks.customizeUiComponent(logTable)
        callbacks.customizeUiComponent(scrollPane)
        callbacks.customizeUiComponent(tabs)        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab(self)       
        # register ourselves as an HTTP listener
        callbacks.registerHttpListener(self)        
        return       
    #
    # implement ITab
    #   
    def getTabCaption(self):
        return "sensitive"   
    def getUiComponent(self):
        return self._splitpane        
    #
    # implement IHttpListener
    #    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # only process requests
        if messageIsRequest:
            return        
        # 敏感信息
        bodyStr=messageInfo.getResponse().tostring()
        retel = re.compile(r'((\W13[0-9]|14[57]|15[012356789]|17[0-9]|18[012356789])\d{8}\W)')
        reip = re.compile(r'(((25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d)))\.){3}(25[0-5]|2[0-4]\d|((1\d{2})|([1-9]?\d))))')
        recardid = re.compile(r'(\W(\d{15}|\d{18})\W)')
        reemail = re.compile(r'(\W[A-Za-z0-9\u4e00-\u9fa5]+@[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)+\W)')
        recardbin = re.compile(r'((\W[1-9]{1})(\d{15}|\d{18})\W)')
        tel = retel.findall(bodyStr)
        ip=reip.findall(bodyStr)
        cardid=recardid.findall(bodyStr)
        email=reemail.findall(bodyStr)
        cardbin=recardbin.findall(bodyStr)
        # create a new log entry with the message details
        if len(tel)|len(cardid)|len(ip)|len(email)|len(cardbin):
            sensitive=''
            tels='{tel:'
            ips='{ip:'
            cardids='{cardid:'
            emails='{email:'
            cardbins='{cardbin:'
            if tel:
                for i in range(len(tel)):
                    tels=tels+tel[i][0]
            tels=tels+'} '
            if ip:
                for i in range(len(ip)):
                    ips=ips+ip[i][0]
            ips=ips+'} '
            if cardid:
                for i in range(len(cardid)):
                    cardids=cardids+cardid[i][0]
            cardids=cardids+'} '
            if email:
                for i in range(len(email)):
                    emails=emails+email[i][0]
            emails=emails+'} '
            if cardbin:
                for i in range(len(cardbin)):
                    cardbins=cardbins+cardbin[i][0]
            cardbins=cardbins+'} '
            sensitive=tels+ips+cardids+emails+cardbins
            self._lock.acquire()
            row = self._log.size()
            self._log.add(LogEntry(toolFlag, self._callbacks.saveBuffersToTempFiles(messageInfo), self._helpers.analyzeRequest(messageInfo).getUrl(), sensitive))
            self.fireTableRowsInserted(row, row)
            self._lock.release()
    #
    # extend AbstractTableModel
    #   
    def getRowCount(self):
        try:
            return self._log.size()
        except:
            return 0
    def getColumnCount(self):
        return 4

    def getColumnName(self, columnIndex):
        if columnIndex == 0:
            return "id"
        if columnIndex == 1:
        	return "tools"
        if columnIndex == 2:
        	return "url"
        if columnIndex == 3:
        	return "sensitive"
        return ""
    def getValueAt(self, rowIndex, columnIndex):
        logEntry = self._log.get(rowIndex)
        if columnIndex == 0:
            return rowIndex
        if columnIndex == 1:
            return self._callbacks.getToolName(logEntry._tool)
        if columnIndex == 2:
        	return logEntry._url.toString()
        if columnIndex == 3:
        	return logEntry._sensitive
        return ""
    #
    # implement IMessageEditorController
    # this allows our request/response viewers to obtain details about the messages being displayed
    #   
    def getHttpService(self):
        return self._currentlyDisplayedItem.getHttpService()

    def getRequest(self):
        return self._currentlyDisplayedItem.getRequest()

    def getResponse(self):
        return self._currentlyDisplayedItem.getResponse()
#
# extend JTable to handle cell selection
#   
class Table(JTable):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)   
    def changeSelection(self, row, col, toggle, extend):
        # show the log entry for the selected row
        logEntry = self._extender._log.get(row)
        self._extender._requestViewer.setMessage(logEntry._requestResponse.getRequest(), True)
        self._extender._responseViewer.setMessage(logEntry._requestResponse.getResponse(), False)
        self._extender._currentlyDisplayedItem = logEntry._requestResponse       
        JTable.changeSelection(self, row, col, toggle, extend)    
#
# class to hold details of each log entry
#
class LogEntry:
    def __init__(self, tool, requestResponse, url, sensitive):
        self._tool = tool
        self._requestResponse = requestResponse
        self._url = url
        self._sensitive = sensitive
