# -*- coding: utf8 -*-


from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response
from django.template import Context
from django.template import RequestContext
from django.template.loader import get_template
from django.core.context_processors import csrf
from django.views.decorators.csrf import csrf_protect
from django.contrib import auth
import xdrlib, sys, xlrd, datetime, copy

from models import *

def hello(request):
    return HttpResponse("Hello world")

@csrf_protect
def login(request):
	if request.method == 'GET':
		return show_login_view(request, False)
		# return render_to_response('/static/login.html')
	elif request.method == 'POST':
		username = request.POST.get('user', '')
		password = request.POST.get('password', '')
		user     = auth.authenticate(username=username, password=password)
		print "user: %s, password: %s" % (username, password)
		if user is not None and user.is_active:
			# Correct password, and the user is marked "active"
			auth.login(request, user)
			# Redirect to a success page.
			return HttpResponseRedirect("/main/")
		else:
			return show_login_view(request, True)

		# if ('user' in request.POST and request.POST['user']) and \
		# 	('password' in request.POST and request.POST['password']):
		# 	user = User.objects.filter(user = request.POST['user'], password = request.POST['password'])
		# 	if user:
		# 		return HttpResponseRedirect('/main')
		# else:
		# 	print "error"
		# 	t    = get_template('login.html')
		# 	html = t.render(RequestContext(request, {'error': True}))
		# 	return HttpResponse(html)


def main(request):
	if request.user.is_authenticated():
		t      = get_template('index.html')
		action = request.GET.get('action', '')
		print "action: %s" % (action)
		if action == '':
			return show_default_main_view(request, t)
		elif action == 'msg':
			return show_msg_view(request, t)
		elif action == 'req_valid':
			return show_req_valid_view(request, t)
		elif action == 'check_onu_valid':
			return show_check_valid_view(request, t)
		elif action == 'check_eoc_valid':
			return show_check_valid_view(request, t)
		elif action == 'query':
			return show_query_view(request, t)
	else:
		return show_login_view(request, True)


# ============================help function=====================================
def show_login_view(request, is_error):
	t    = get_template('login.html')
	html = t.render(RequestContext(request, {'error': is_error}))
	return HttpResponse(html)

def show_default_main_view(request, t_html):
	action = request.GET.get('action', '')
	dic = {'user': request.user.username, 
		   'action': action,
		   'msg_len': get_message_len(request.user.username)
		  }
	return HttpResponse(t_html.render(RequestContext(request, dic)))
	

def show_msg_view(request, t_html):
	action  = request.GET.get('action', '')
	my_msgs = Message.objects.filter(user = request.user.username).order_by('-report_date').order_by('is_read')
	dic = {'user': request.user.username, 
		   'action': action,
		   'msg_list': my_msgs,
		   'msg_len': get_message_len(request.user.username)
		  }
	
	response = HttpResponse(t_html.render(RequestContext(request, dic)))

	# for msg in my_msgs:
	# 	msg.is_read = True
	# 	msg.save()
	return response


def get_message_len(username):
	return len(Message.objects.filter(user = username, is_read = False))

def query_msg(request):
	msg_id = request.GET['msg_id']
	msg = Message.objects.get(msg_id = msg_id)
	if msg.msg_type == 1:
		if msg.dev_type == 1:
			report_date = msg.report_date.strftime('%Y-%m-%d %H:%M:%S')
			return HttpResponseRedirect('/main?action=check_onu_valid&report_date=%s' % (report_date))
		elif msg.dev_type == 2:
			report_date = msg.report_date.strftime('%Y-%m-%d %H:%M:%S')
			return HttpResponseRedirect('/main?action=check_eoc_valid&report_date=%s' % (report_date))


def show_req_valid_view(request, t_html):
	action = request.GET.get('action', '')
	dic = {'user': request.user.username, 
		   'action': action,
		   'msg_len': get_message_len(request.user.username),
		   'valider_list': User.objects.all()
		  }
	return HttpResponse(t_html.render(RequestContext(request, dic)))

def show_check_valid_view(request, t_html):
	action      = request.GET.get('action', '')
	report_date = request.GET.get('report_date', '')
	username    = request.user.username
	dic = {'user': username, 
		   'action': action,
		   'msg_len': get_message_len(username)
		  }
	if action == 'check_onu_valid':
		dic['onu_check_list'] = get_onu_detail_report(username, report_date)
	elif action == 'check_eoc_valid':
		dic['eoc_check_list'] = get_eoc_detail_report(username)
	return HttpResponse(t_html.render(RequestContext(request, dic)))


def get_onu_detail_report(username, report_date):
	if report_date == '':
		return ONUDetailReport.objects.raw(
		('select install_valid_devonu_tmp.dev_id, user, date, addr_1, addr_2, addr_detail, dev_name, mac_addr, port_remark '
				'from install_valid_devonu_tmp, install_valid_devreport '
				'where to_who=\'%s\' and dev_type=1 and is_valid=0 '
				'and install_valid_devonu_tmp.dev_id=install_valid_devreport.dev_id '
				'order by date') % (username))
	else:
		return ONUDetailReport.objects.raw(
		('select install_valid_devonu_tmp.dev_id, user, date, addr_1, addr_2, addr_detail, dev_name, mac_addr, port_remark '
				'from install_valid_devonu_tmp, install_valid_devreport '
				'where to_who=\'%s\' and dev_type=1 and is_valid=0 and install_valid_devreport.date=\'%s\' '
				'and install_valid_devonu_tmp.dev_id=install_valid_devreport.dev_id '
				'order by date') % (username, datetime.datetime.strptime(report_date, '%Y-%m-%d %H:%M:%S')))

def get_eoc_detail_report(username):
	return EOCDetailReport.objects.raw(
		('select install_valid_deveoc_tmp.dev_id, user, date, addr_1, addr_2, addr_detail, '
		 'line_box_type, dev_box_type, install_valid_deveoc_tmp.dev_type, cover_users, '
		 'model, manager_ip, ip_mask, gateway, manager_vlan, port_begin_valn, port_end_valn '
				'from install_valid_deveoc_tmp, install_valid_devreport '
				'where to_who=\'%s\' and install_valid_devreport.dev_type=2 and is_valid=0 '
				'and install_valid_deveoc_tmp.dev_id=install_valid_devreport.dev_id '
				'order by date') % (username))

@csrf_protect
def upload(request):
	if request.method == 'POST' and request.FILES['file'] is not None:
		print "ok, upload: %s" % (request.FILES['file'])
		handle_upload(request.FILES['file'], request)
	t = get_template('upload_succ.html')
	return HttpResponse(t.render(RequestContext(request, {})))


def handle_upload(f, request):
	# to-do: temp文件要唯一
	tmp_file = ('%s_tmp.xlsx') % (request.user.username)
	print tmp_file
	destination = open(tmp_file, 'wb+')
	for chunk in f.chunks():
		destination.write(chunk)
	destination.close()

	xml_data = xlrd.open_workbook(tmp_file)
	upload_onu_dev(request, xml_data)
	upload_eoc_dev(request, xml_data)


def upload_onu_dev(request, xml_data):
	table    = xml_data.sheet_by_name(u'onu')
	dev_type = 1
	date     = datetime.datetime.now()
	has_data = False
	# 循环行列表数据
	for i in range(1, table.nrows):
		has_data = True
		# 保存等待验收的设备临时数据
		dev = DevONU_TMP(addr_1      = table.cell(i, 0).value,
						 addr_2      = table.cell(i, 1).value,
						 addr_detail = table.cell(i, 2).value,
						 dev_name    = table.cell(i, 3).value,
						 mac_addr    = table.cell(i, 4).value,
						 port_remark = table.cell(i, 5).value)
		dev.save()
		dev_id = dev.dev_id
		# 然后保存提交记录
		report = DevReport(	user     = request.user.username, 
							to_who   = request.POST.get('valider', ''),
							dev_id   = dev_id,
							dev_type = dev_type,
							date     = date,
							is_valid = False)
		report.save()
	# 再向验证者发送消息
	if has_data:
		msg = Message(user        = request.POST.get('valider', ''),
					  msg_type    = 1,
					  from_who    = request.user.username,
					  dev_type    = dev_type,
					  report_date = date,
					  is_read     = False)
		msg.save()

def upload_eoc_dev(request, xml_data):
	table    = xml_data.sheet_by_name(u'eoc')
	date     = datetime.datetime.now()
	dev_type = 2
	has_data = False
	# 循环行列表数据
	for i in range(1, table.nrows):
		has_data = True
		# 保存等待验收的设备临时数据
		dev = DevEOC_TMP(addr_1          = table.cell(i, 0).value,
						 addr_2          = table.cell(i, 1).value,
						 addr_detail     = table.cell(i, 2).value,
						 line_box_type   = table.cell(i, 3).value,
						 dev_box_type    = table.cell(i, 4).value,
						 dev_type        = table.cell(i, 5).value,
						 cover_users     = table.cell(i, 6).value,
						 model           = table.cell(i, 7).value,
						 manager_ip      = table.cell(i, 8).value,
						 ip_mask         = table.cell(i, 9).value,
						 gateway         = table.cell(i, 10).value,
						 manager_vlan    = table.cell(i, 11).value,
						 port_begin_valn = table.cell(i, 12).value,
						 port_end_valn   = table.cell(i, 13).value)
		dev.save()
		dev_id = dev.dev_id
		# 然后保存提交记录
		report = DevReport(	user     = request.user.username, 
							to_who   = request.POST.get('valider', ''),
							dev_id   = dev_id,
							dev_type = dev_type,
							date     = date,
							is_valid = False)
		report.save()
	# 再向验证者发送消息
	if has_data:
		msg = Message(user        = request.POST.get('valider', ''),
					  msg_type    = 1,
					  from_who    = request.user.username,
					  dev_type    = dev_type,
					  report_date = date,
					  is_read     = False)
		msg.save()

def valid_dev(request):
	print request.POST.getlist('_selected_action')
	print "dev_type: %s" % (request.GET.get('dev_type', ''))
	checked_list = request.POST.getlist('_selected_action')
	dev_type   = request.GET['dev_type']
	valid_date = datetime.datetime.now()
	if dev_type == 'check_onu_valid':
		valid_onu_dev(checked_list, valid_date)
	elif dev_type == 'check_eoc_valid':
		valid_eoc_dev(checked_list, valid_date)

	t = get_template('valid_succ.html')
	return HttpResponse(t.render(RequestContext(request, {})))

def valid_onu_dev(checked_list, valid_date):
	dev_type        = 1
	report_msg_list = {}
	for report_dev_id in checked_list:
		dev_tmp    = DevONU_TMP.objects.get(dev_id = report_dev_id)
		dev = DevONU(addr_1      = dev_tmp.addr_1,
					 addr_2      = dev_tmp.addr_2,
					 addr_detail = dev_tmp.addr_detail,
					 dev_name    = dev_tmp.dev_name,
					 mac_addr    = dev_tmp.mac_addr,
					 port_remark = dev_tmp.port_remark)
		dev.save()
		new_dev_id = dev.dev_id
		dev_tmp.delete()
		# 修改提交记录
		report            = DevReport.objects.filter(dev_id = report_dev_id, dev_type = dev_type)[0]
		report.dev_id     = new_dev_id
		report.valid_date = valid_date
		report.is_valid   = True
		report.save()
		report_msg_list[report.user] = report.to_who
	# 发消息给提交者
	for u in report_msg_list.keys():
		msg = Message(user        = u,
					  msg_type    = 2,
					  from_who    = report_msg_list[u],
					  dev_type    = dev_type,
					  report_date = datetime.datetime.now(),
					  is_read     = False)
		msg.save()

def valid_eoc_dev(checked_list, valid_date):
	dev_type = 2
	report_msg_list = {}
	for report_dev_id in checked_list:
		dev_tmp    = DevEOC_TMP.objects.get(dev_id = report_dev_id)
		dev = DevEOC(addr_1          = dev_tmp.addr_1,
					 addr_2          = dev_tmp.addr_2,
					 addr_detail     = dev_tmp.addr_detail,
					 line_box_type   = dev_tmp.line_box_type,
					 dev_box_type    = dev_tmp.dev_box_type,
					 dev_type        = dev_tmp.dev_type,
					 cover_users     = dev_tmp.cover_users,
					 model           = dev_tmp.model,
					 manager_ip      = dev_tmp.manager_ip,
					 ip_mask         = dev_tmp.ip_mask,
					 gateway         = dev_tmp.gateway,
					 manager_vlan    = dev_tmp.manager_vlan,
					 port_begin_valn = dev_tmp.port_begin_valn,
					 port_end_valn   = dev_tmp.port_end_valn)
		# 保存验收成功的数据到正式的表中
		dev.save()
		new_dev_id = dev.dev_id
		# 删除临时表的数据
		dev_tmp.delete()
		# 修改提交记录
		report            = DevReport.objects.filter(dev_id = report_dev_id, dev_type = dev_type)[0]
		report.dev_id     = new_dev_id
		report.valid_date = valid_date
		report.is_valid   = True
		report.save()
		report_msg_list[report.user] = report.to_who
	# 发消息给提交者
	for u in report_msg_list.keys():
		msg = Message(user        = u,
					  msg_type    = 2,
					  from_who    = report_msg_list[u],
					  dev_type    = dev_type,
					  report_date = datetime.datetime.now(),
					  is_read     = False)
		msg.save()
