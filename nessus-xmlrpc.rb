#
# = nessus-xmlrpc.rb: communicate with Nessus(4.2+) over XML RPC interface
#
# Author:: Vlatko Kosturjak
#
# (C) Vlatko Kosturjak, Kost. Distributed under GPL.

require 'uri'
require 'net/https'
require 'rexml/document'

# Usage:
# 
# require 'nessus-xmlrpc'
# n=NessusXMLRPC::NessusXMLRPC.new('https://localhost:8834','user','pass');
# if n.logged_in
# 	id,name = n.get_policy_first
# 	puts "using policy ID: " + id + " with name: " + name
# 	uid=n.scan_new(id,"textxmlrpc","127.0.0.1")
#	puts "status: " + n.scan_status(uid)
# 	while not n.scan_finished(uid)
# 		sleep 10
# 	end
#	content=n.file_report_download(uid)
# 	File.open('report.xml', 'w') {|f| f.write(content) }
# end

module NessusXMLRPC 

class NessusXMLRPC 
	# initialize object with URL of Nessus
	def initialize(url,user,pass)
		if url == ''
			@nurl="https://localhost:8834/"
		else
			if url =~ /\/$/
				@nurl=url
			else
				@nurl=url + "/"
			end
		end
		@token=''
		login(user,pass)
	end

	# checks if we logged in correctly
	def logged_in
		if @token == ''
			return false
		else
			return true
		end
	end	

	# send standard Nessus XML request and check
	# return: rexml/document root
	def nessus_request(uri, post_data) 
		url = URI.parse(@nurl + uri) 
		request = Net::HTTP::Post.new( url.path )
		request.set_form_data( post_data )
					  
		@https = Net::HTTP.new( url.host, url.port )
		https.use_ssl = true
		https.verify_mode = OpenSSL::SSL::VERIFY_NONE
		# puts request
		begin
		  response = https.request( request )
		rescue 
		  puts "[e] error connecting to server. check URL: " + @nurl 
		  exit
		end
		# puts response.body
		docxml = REXML::Document.new(response.body)
		begin 
		status = docxml.root.elements['status'].text
		rescue
			puts "[e] error in XML parsing"
		end
		if status == "OK"
			return docxml 
		else 
			return ''
		end
	end
	# send standard Nessus XML request and check
	# return: rexml/document root
	def nessus_file_request(uri, post_data) 
		url = URI.parse(@nurl + uri) 
		request = Net::HTTP::Post.new( url.path )
		request.set_form_data( post_data )
					  
		@https = Net::HTTP.new( url.host, url.port )
		https.use_ssl = true
		https.verify_mode = OpenSSL::SSL::VERIFY_NONE
		# puts request
		begin
			response = https.request( request )
		rescue 
			puts "[e] error connecting to server. check URL: " + @nurl
			exit
		end
		# puts response.body
		return response.body
	end
	
	# login with user & pass and sets object-wide @token 
	def login(user, pass)
		post = { "login" => user, "password" => pass }
		docxml=nessus_request('login', post)
		if docxml == '' 
			@token=''
		else
			@token = docxml.root.elements['contents'].elements['token'].text
			@name = docxml.root.elements['contents'].elements['user'].elements['name'].text
			@admin = docxml.root.elements['contents'].elements['user'].elements['admin'].text
			# puts "Got token:" + @token
		end
			
	end
	
	# initiate new scan with policy id, descriptive name and list of targets
	# returns: uuid of scan
	def scan_new(policy_id,scan_name,target)
		post= { "token" => @token, "policy_id" => policy_id, "scan_name" => scan_name, "target" => target } 
		docxml=nessus_request('scan/new', post)
		if docxml == '' 
			return ''
		else
			uuid=docxml.root.elements['contents'].elements['scan'].elements['uuid'].text
			return uuid
		end	
	end

	# returns array of uids of active scans
	def scan_list_uids
		post= { "token" => @token } 
		docxml=nessus_request('scan/list', post)
		uuids=Array.new
		docxml.root.elements['contents'].elements['scans'].elements['scanList'].each_element('//scan') {|scan| uuids.push(scan.elements['uuid'].text) }
		return uuids
	end

	# returns array of hash of active scans
	def scan_list_hash
		post= { "token" => @token } 
		docxml=nessus_request('scan/list', post)
		scans=Array.new
		docxml.root.elements['contents'].elements['scans'].elements['scanList'].each_element('//scan') {|scan| 
			entry=Hash.new
			entry['id']=scan.elements['uuid'].text
			entry['name']=scan.elements['readableName'].text
			entry['current']=scan.elements['completion_current'].text;
			entry['total']=scan.elements['completion_total'].text;		
			scans.push(entry) 
		}
		return scans
	end

	# get policy by textname and return policyID
	def get_policy_id(textname) 
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		docxml.root.elements['contents'].elements['policies'].each_element('//policy') {|policy|
			if policy.elements['policyName'].text == textname
				return policy.elements['policyID'].text 
			end
		}
		return ''
	end	

	# get first policy from server and returns: policyID, policyName
	def get_policy_first
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		docxml.root.elements['contents'].elements['policies'].each_element('//policy') {|policy|
				return policy.elements['policyID'].text, policy.elements['policyName'].text
		}
	end	

	# stop scan identified by scan_uuid
	def scan_stop(uuid)
		post= { "token" => @token, "scan_uuid" => uuid } 
		docxml=nessus_request('scan/stop', post)
		return docxml
	end
	# stop all active scans 
	def scan_stop_all
		b=scan_list_uids
		b.each {|uuid|
		scan_stop(uuid)
		}
		return b
	end
	# pause scan identified by scan_uuid
	def scan_pause(uuid)
		post= { "token" => @token, "scan_uuid" => uuid } 
		docxml=nessus_request('scan/pause', post)
		return docxml
	end
	# pause all active scans 
	def scan_pause_all
		b=scan_list_uids
		b.each {|uuid|
		scan_pause(uuid)
		}
		return b
	end
	# remove scan identified by scan_uuid
	def scan_resume(uuid)
		post= { "token" => @token, "scan_uuid" => uuid } 
		docxml=nessus_request('scan/resume', post)
		return docxml
	end
	# resume all active scans 
	def scan_resume_all
		b=scan_list_uids
		b.each {|uuid|
		scan_resume(uuid)
		}
		return b
	end

	# check status of scan
	def scan_status(uuid)
		post= { "token" => @token, "report" => uuid } 
		docxml=nessus_request('report/list', post)
		docxml.root.elements['contents'].elements['reports'].each_element('//report') { |report|
			if report.elements['name'].text == uuid
				return (report.elements['status'].text)
			end
		}
		return ''
	end

	# check if scan is finished (completed to be exact)
	def scan_finished(uuid)
		status=scan_status(uuid)
		if status == "completed"
			return true
		else
			return false
		end
	end
	
	# get report by reportID and return XML file
	def file_report_download(report)
		post= { "token" => @token, "report" => report } 
		file=nessus_file_request('file/report/download', post)
		return file
	end

	# get report by reportID and return XML file (version 1)
	def file_report1_download(report)
		post= { "token" => @token, "report" => report, "v1" => "true" } 
		file=nessus_file_request('file/report/download', post)
		return file
	end
	
	# delete report by reportID
	def report_delete(report)
		post= { "token" => @token, "report" => report } 
		docxml=nessus_request('report/delete', post)
		return docxml
	end
	# get list of reports and return XML tree reports
	def report_list
		post= { "token" => @token } 
		docxml=nessus_request('report/list', post)
		status = docxml.root.elements['status'].text
		if status == "OK"
			return docxml.root.elements['contents'].elements['reports']
		else 
			return ''
		end
	end

	def policy_list_names
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		list = Array.new
		docxml.root.elements['contents'].elements['policies'].each_element('//policy') {|policy|
				list.push policy.elements['policyName'].text
		}
		return list
	end
	# ToDo items
	def policy_list
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		return docxml
	end
	def plugins_list
		post= { "token" => @token } 
		docxml=nessus_request('plugins/list', post)
		return docxml
	end
	def users_list
		post= { "token" => @token } 
		docxml=nessus_request('users/list', post)
		return docxml
	end
	# get hosts for particular scan
	def scan_hosts(uuid)
		post= { "token" => @token, "scan_uuid" => uuid } 
		docxml=nessus_request('scan/hosts', post)
		return docxml
	end
	# returns XML part of list of scans
	def scan_list
		post= { "token" => @token } 
		docxml=nessus_request('scan/list', post)
		return docxml
	end
	
end # end of NessusXMLRPC::Class

nokogiri=true
begin
	require 'nokogiri'
rescue Exception
	nokogiri=false
end

if nokogiri
class NessusXMLRPCnokogiri < NessusXMLRPC
	def nessus_request(uri, post_data) 
		url = URI.parse(@nurl + uri) 
		request = Net::HTTP::Post.new( url.path )
		request.set_form_data( post_data )
					  
		https = Net::HTTP.new( url.host, url.port )
		https.use_ssl = true
		https.verify_mode = OpenSSL::SSL::VERIFY_NONE
		# puts request
		begin
		  response = https.request( request )
		rescue 
		  puts "[e] error connecting to server. check URL: " + @nurl 
		  exit
		end
		# puts response.body
		docxml = Nokogiri::XML.parse(response.body)
		begin 
		status = docxml.xpath("/reply/status").collect(&:text)[0]
		rescue
			puts "[e] error in XML parsing"
		end
		if status == "OK"
			return docxml 
		else 
			return ''
		end
	end
	def login(user, pass)
		post = { "login" => user, "password" => pass }
		docxml=nessus_request('login', post)
		if docxml == '' 
			@token=''
		else
			@token = docxml.xpath("/reply/contents/token").collect(&:text)[0]
			@name = docxml.xpath("/reply/contents/user/name").collect(&:text)[0]
			@admin = docxml.xpath("/reply/contents/user/admin").collect(&:text)[0]
		end
			
	end
	# initiate new scan with policy id, descriptive name and list of targets
	# returns: uuid of scan
	def scan_new(policy_id,scan_name,target)
		post= { "token" => @token, "policy_id" => policy_id, "scan_name" => scan_name, "target" => target } 
		docxml=nessus_request('scan/new', post)
		if docxml == '' 
			return ''
		else
			uuid=docxml.xpath("/reply/contents/scan/uuid").collect(&:text)[0]
			return uuid
		end	
	end
	def report_list
		post= { "token" => @token } 
		docxml=nessus_request('report/list', post)
		return docxml
	end
	# check status of scan
	def scan_status(uuid)
		post= { "token" => @token, "report" => uuid } 
		docxml=nessus_request('report/list', post)
		return docxml.xpath("/reply/contents/reports/report/name[text()='"+uuid+"']/../status").collect(&:text)[0]
	end
	# returns array of uids of active scans
	def scan_list_uids
		post= { "token" => @token } 
		docxml=nessus_request('scan/list', post)
		return docxml.xpath("/reply/contents/scans/scanList/scan/uuid").collect(&:text)
	end
	# get policy by textname and return policyID
	def get_policy_id(textname) 
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		return docxml.xpath("/reply/contents/policies/policy/policyName[text()='"+textname+"']/..policyID").collect(&:text)[0]
	end	
	# get first policy from server and returns: policyID, policyName
	def get_policy_first
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		id=docxml.xpath("/reply/contents/policies/policy/policyID").collect(&:text)[0]
		name=docxml.xpath("/reply/contents/policies/policy/policyName").collect(&:text)[0]
		return id, name
	end	
	def policy_list_names
		post= { "token" => @token } 
		docxml=nessus_request('policy/list', post)
		return docxml.xpath("/reply/contents/policies/policy/policyName").collect(&:text)
	end
end # end of NessusXMLRPCnokogiri::Class
end # if nokogiri

end # of Module

